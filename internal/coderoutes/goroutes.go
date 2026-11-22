package coderoutes

import (
	"bufio"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The Go extractor reads every package with go/parser (no type checking,
// no build) and follows router values through the code: a router made by
// a known constructor or passed as a router-typed parameter, a sub-router
// made with a prefix (mux PathPrefix(...).Subrouter(), gin and echo
// Group(prefix), chi Route(prefix, fn), Gitea Group(prefix, fn)), and the
// routes registered on them (Handle(...).Methods(...), HandleFunc, Get,
// GET, Methods("GET,POST", ...), Combo(...).Get(...), Any). Calls into
// functions of the same source tree are followed with the routers they
// are given, so a prefix set by a caller reaches the routes its callees
// register; Mount(prefix, pkg.Routes()) gives every route Routes
// registers that prefix. A router kept in a struct field
// (api.BaseRoutes.Channel) is followed by the field's expression.

type goResult struct {
	routes               []found
	unparsed, unresolved int
	truncated            bool // the walk hit maxWalk
}

// memoKey names one walk of a function: the function and the routers it
// is given. Walking it again with the same routers finds the same routes.
func memoKey(f goFunc, args []*string, mount string, recv *string) string {
	var b strings.Builder
	b.WriteString(f.pkg.dir + "\x00" + strconv.Itoa(int(f.decl.Pos())) + "\x00" + mount)
	for _, a := range append([]*string{recv}, args...) {
		if a == nil {
			b.WriteString("\x00-")
		} else {
			b.WriteString("\x00=" + *a)
		}
	}
	return b.String()
}

// goPkg is one parsed package: its files and its string constants.
type goPkg struct {
	dir    string
	name   string
	files  []*ast.File
	consts map[string]ast.Expr
}

type goFunc struct {
	pkg  *goPkg
	file *ast.File
	decl *ast.FuncDecl
}

type goIndex struct {
	fset     *token.FileSet
	pkgs     map[string]*goPkg   // by directory
	modules  map[string]string   // module path -> directory
	funcs    map[string][]goFunc // "dir.Name" for functions, "#Name" for methods
	routing  map[*ast.FuncDecl]bool
	children map[*ast.FuncDecl][]*ast.FuncDecl
}

// Router constructors: package-qualified calls that return a new router.
var goNewRouter = map[string]bool{
	"mux.NewRouter": true, "chi.NewRouter": true, "chi.NewMux": true, "web.NewRouter": true,
	"gin.New": true, "gin.Default": true, "echo.New": true, "http.NewServeMux": true,
	"httprouter.New": true, "fiber.New": true,
}

// Router types: a parameter of one of these types is a router.
var goRouterType = map[string]bool{
	"mux.Router": true, "chi.Router": true, "chi.Mux": true, "web.Router": true,
	"gin.Engine": true, "gin.RouterGroup": true, "gin.IRouter": true, "gin.IRoutes": true,
	"echo.Echo": true, "echo.Group": true, "http.ServeMux": true, "httprouter.Router": true,
}

// Methods that register a route for one HTTP method: name -> method.
var goMethodCalls = map[string]string{
	"Get": "GET", "GET": "GET", "Head": "HEAD", "HEAD": "HEAD",
	"Post": "POST", "POST": "POST", "Put": "PUT", "PUT": "PUT",
	"Patch": "PATCH", "PATCH": "PATCH", "Delete": "DELETE", "DELETE": "DELETE",
	"Options": "OPTIONS", "OPTIONS": "OPTIONS", "Any": "*",
}

// Calls that read a query parameter by name, on a request or context.
var goQueryCalls = map[string]bool{
	"FormValue": true, "FormString": true, "FormInt": true, "FormInt64": true, "FormBool": true,
	"FormTrim": true, "FormStrings": true, "FormOptionalBool": true, "Query": true,
	"QueryParam": true, "DefaultQuery": true, "GetQuery": true, "QueryArray": true,
}

var httpMethodConst = map[string]string{
	"MethodGet": "GET", "MethodHead": "HEAD", "MethodPost": "POST", "MethodPut": "PUT",
	"MethodPatch": "PATCH", "MethodDelete": "DELETE", "MethodOptions": "OPTIONS",
}

func goRoutes(files []srcFile, root string) goResult {
	ix := &goIndex{
		fset: token.NewFileSet(), pkgs: map[string]*goPkg{}, modules: map[string]string{},
		funcs: map[string][]goFunc{}, routing: map[*ast.FuncDecl]bool{}, children: map[*ast.FuncDecl][]*ast.FuncDecl{},
	}
	var res goResult
	for _, f := range files {
		af, err := parser.ParseFile(ix.fset, f.path, f.data, parser.SkipObjectResolution)
		if err != nil {
			res.unparsed++
			continue
		}
		dir := filepath.Dir(f.path)
		p := ix.pkgs[dir]
		if p == nil {
			p = &goPkg{dir: dir, name: af.Name.Name, consts: map[string]ast.Expr{}}
			ix.pkgs[dir] = p
		}
		p.files = append(p.files, af)
	}
	ix.readModules(root)
	for _, p := range sortedPkgs(ix.pkgs) {
		for _, af := range p.files {
			for _, d := range af.Decls {
				switch d := d.(type) {
				case *ast.GenDecl:
					if d.Tok == token.CONST || d.Tok == token.VAR {
						for _, s := range d.Specs {
							vs := s.(*ast.ValueSpec)
							for i, n := range vs.Names {
								if i < len(vs.Values) {
									p.consts[n.Name] = vs.Values[i]
								}
							}
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					key := p.dir + "." + d.Name.Name
					if d.Recv != nil {
						key = "#" + d.Name.Name
					}
					ix.funcs[key] = append(ix.funcs[key], goFunc{p, af, d})
				}
			}
		}
	}
	ix.markRouting()
	w := &goWalker{ix: ix, global: map[string]string{}, res: &res, onStack: map[*ast.FuncDecl]bool{}, done: map[string]bool{}, budget: maxWalk}
	// Walk every routing function no other routing function calls, each
	// with an empty prefix; callees are reached through their callers.
	called := map[*ast.FuncDecl]bool{}
	for _, cs := range ix.children {
		for _, c := range cs {
			called[c] = true
		}
	}
	var roots []goFunc
	for _, key := range sortedKeys(ix.funcs) {
		for _, f := range ix.funcs[key] {
			if ix.routing[f.decl] && !called[f.decl] {
				roots = append(roots, f)
			}
		}
	}
	for _, f := range roots {
		w.walkFunc(f, nil, "", nil)
	}
	// Routing functions only reached through a cycle of calls.
	for _, key := range sortedKeys(ix.funcs) {
		for _, f := range ix.funcs[key] {
			if ix.routing[f.decl] && !w.walked[f.decl] {
				w.walkFunc(f, nil, "", nil)
			}
		}
	}
	return res
}

func sortedPkgs(m map[string]*goPkg) []*goPkg {
	out := make([]*goPkg, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readModules reads the go.mod files of the tree, so an import path
// resolves to a directory of it.
func (ix *goIndex) readModules(root string) {
	seen := map[string]bool{}
	for dir := range ix.pkgs {
		for d := dir; ; d = filepath.Dir(d) {
			if !seen[d] {
				seen[d] = true
				if b, err := readSmall(filepath.Join(d, "go.mod")); err == nil {
					sc := bufio.NewScanner(bytes.NewReader(b))
					for sc.Scan() {
						if f := strings.Fields(sc.Text()); len(f) == 2 && f[0] == "module" {
							ix.modules[strings.Trim(f[1], `"`)] = d
						}
					}
				}
			}
			if d == root || d == filepath.Dir(d) || !strings.HasPrefix(d, root) {
				break
			}
		}
	}
}

// importDir returns the directory of the package a file imports as name.
func (ix *goIndex) importDir(af *ast.File, name string) string {
	for _, im := range af.Imports {
		ip, _ := strconv.Unquote(im.Path.Value)
		local := path.Base(ip)
		if im.Name != nil {
			local = im.Name.Name
		}
		if local != name {
			// The package's own name may differ from its last path
			// element (gitea's routers/api/v1 is package v1, imported
			// as apiv1).
			if im.Name != nil {
				continue
			}
			if d := ix.dirOf(ip); d == "" || ix.pkgs[d] == nil || ix.pkgs[d].name != name {
				continue
			}
		}
		return ix.dirOf(ip)
	}
	return ""
}

func (ix *goIndex) dirOf(importPath string) string {
	best, dir := "", ""
	for mod, d := range ix.modules {
		if (importPath == mod || strings.HasPrefix(importPath, mod+"/")) && len(mod) > len(best) {
			best, dir = mod, filepath.Join(d, filepath.FromSlash(strings.TrimPrefix(importPath, mod)))
		}
	}
	return dir
}

// markRouting finds the functions that register routes or make routers,
// directly or through the functions they call, so only those are walked.
func (ix *goIndex) markRouting() {
	direct := map[*ast.FuncDecl]bool{}
	for _, key := range sortedKeys(ix.funcs) {
		for _, f := range ix.funcs[key] {
			ast.Inspect(f.decl.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && looksLikeRouting(sel.Sel.Name, call.Args) {
					direct[f.decl] = true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					name := sel.Sel.Name
					if x, ok := sel.X.(*ast.Ident); ok && goNewRouter[x.Name+"."+name] {
						direct[f.decl] = true
					}
				}
				for _, c := range ix.callees(f, call) {
					ix.children[f.decl] = append(ix.children[f.decl], c.decl)
				}
				return true
			})
		}
	}
	for d := range direct {
		ix.routing[d] = true
	}
	// A function that calls a routing function routes too.
	for changed := true; changed; {
		changed = false
		for parent, cs := range ix.children {
			if ix.routing[parent] {
				continue
			}
			for _, c := range cs {
				if ix.routing[c] {
					ix.routing[parent] = true
					changed = true
					break
				}
			}
		}
	}
	// Keep only edges to routing functions.
	for parent, cs := range ix.children {
		var keep []*ast.FuncDecl
		for _, c := range cs {
			if ix.routing[c] {
				keep = append(keep, c)
			}
		}
		ix.children[parent] = keep
	}
}

// looksLikeRouting reports whether a call is shaped like a route
// registration or a router group, before any router is known: the
// method-named calls (Get, Post...) only with a path-shaped literal first
// argument and a handler, so cache.Get(key) does not make every caller a
// routing function.
func looksLikeRouting(name string, args []ast.Expr) bool {
	switch name {
	case "Handle", "HandleFunc", "PathPrefix", "Mount", "Combo", "Subrouter":
		return true
	case "Group", "Route":
		for _, a := range args {
			if _, ok := a.(*ast.FuncLit); ok {
				return true
			}
		}
		return len(args) == 1 && isPathLit(args[0])
	case "Methods", "Method", "Match":
		return len(args) >= 2
	}
	if _, ok := goMethodCalls[name]; ok {
		return len(args) >= 2 && isPathLit(args[0])
	}
	return false
}

// isPathLit reports a string literal that is empty or starts with "/".
func isPathLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	return err == nil && (s == "" || strings.HasPrefix(s, "/"))
}

// callees returns the functions of the tree a call may run: F() in the
// same package, pkg.F(), or x.M() for a method M (in the caller's package
// when it has one there, else the only one in the tree).
func (ix *goIndex) callees(from goFunc, call *ast.CallExpr) []goFunc {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return ix.funcs[from.pkg.dir+"."+fn.Name]
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			if d := ix.importDir(from.file, x.Name); d != "" {
				return ix.funcs[d+"."+fn.Sel.Name]
			}
		}
		ms := ix.funcs["#"+fn.Sel.Name]
		var same []goFunc
		for _, m := range ms {
			if m.pkg == from.pkg {
				same = append(same, m)
			}
		}
		if len(same) > 0 {
			return same[:1]
		}
		if len(ms) == 1 {
			return ms
		}
	}
	return nil
}

// goWalker walks routing functions in statement order, tracking the
// prefix of each router value.
type goWalker struct {
	ix      *goIndex
	global  map[string]string // routers held in fields and package vars, by expression
	res     *goResult
	onStack map[*ast.FuncDecl]bool
	walked  map[*ast.FuncDecl]bool
	done    map[string]bool // functions walked with the same routers
	budget  int             // statements left to walk
}

// maxWalk bounds the statements walked, so code built to fan out cannot
// stall a scan.
const maxWalk = 5_000_000

// scope is one function walk: its local routers and closures.
type scope struct {
	fn      goFunc
	routers map[string]string       // local variable -> prefix
	funcs   map[string]*ast.FuncLit // local variable -> closure
	mount   *string                 // prefix a mounted function's new router starts at
	parent  *scope
}

func (s *scope) router(name string) (string, bool) {
	for c := s; c != nil; c = c.parent {
		if p, ok := c.routers[name]; ok {
			return p, true
		}
	}
	return "", false
}

func (s *scope) setRouter(name, prefix string) {
	for c := s; c != nil; c = c.parent {
		if _, ok := c.routers[name]; ok {
			c.routers[name] = prefix
			return
		}
	}
	s.routers[name] = prefix
}

func (s *scope) closure(name string) *ast.FuncLit {
	for c := s; c != nil; c = c.parent {
		if f, ok := c.funcs[name]; ok {
			return f
		}
	}
	return nil
}

// walkFunc walks f's body; args are the router prefixes of its
// parameters (nil for unknown), mount the prefix a new router made inside
// it starts at (set when it is mounted: Mount("/api/v1", Routes())).
func (w *goWalker) walkFunc(f goFunc, args []*string, mount string, recv *string) {
	if w.onStack[f.decl] || w.budget <= 0 {
		return
	}
	key := memoKey(f, args, mount, recv)
	if w.done[key] {
		return
	}
	w.done[key] = true
	if w.walked == nil {
		w.walked = map[*ast.FuncDecl]bool{}
	}
	w.walked[f.decl] = true
	w.onStack[f.decl] = true
	defer delete(w.onStack, f.decl)
	sc := &scope{fn: f, routers: map[string]string{}, funcs: map[string]*ast.FuncLit{}, mount: &mount}
	if f.decl.Recv != nil && len(f.decl.Recv.List) > 0 && len(f.decl.Recv.List[0].Names) > 0 {
		if recv != nil || w.isRouterType(f.decl.Recv.List[0].Type) {
			p := ""
			if recv != nil {
				p = *recv
			}
			sc.routers[f.decl.Recv.List[0].Names[0].Name] = p
		}
	}
	w.bindParams(sc, f.decl.Type, args)
	w.stmts(sc, f.decl.Body.List)
}

func (w *goWalker) bindParams(sc *scope, ft *ast.FuncType, args []*string) {
	i := 0
	for _, fld := range ft.Params.List {
		names := fld.Names
		if len(names) == 0 {
			names = []*ast.Ident{nil}
		}
		for _, n := range names {
			if n != nil {
				switch {
				case i < len(args) && args[i] != nil:
					sc.routers[n.Name] = *args[i]
				case w.isRouterType(fld.Type):
					sc.routers[n.Name] = ""
				}
			}
			i++
		}
	}
}

func (w *goWalker) isRouterType(t ast.Expr) bool {
	if st, ok := t.(*ast.StarExpr); ok {
		t = st.X
	}
	if sel, ok := t.(*ast.SelectorExpr); ok {
		if x, ok := sel.X.(*ast.Ident); ok {
			return goRouterType[x.Name+"."+sel.Sel.Name]
		}
	}
	return false
}

func (w *goWalker) stmts(sc *scope, list []ast.Stmt) {
	for _, s := range list {
		if w.budget--; w.budget <= 0 {
			w.res.truncated = true
			return
		}
		w.stmt(sc, s)
	}
}

func (w *goWalker) stmt(sc *scope, s ast.Stmt) {
	switch s := s.(type) {
	case *ast.ExprStmt:
		w.expr(sc, s.X)
	case *ast.AssignStmt:
		for _, r := range s.Rhs {
			w.expr(sc, r)
		}
		if len(s.Lhs) == len(s.Rhs) {
			for i, l := range s.Lhs {
				w.assign(sc, l, s.Rhs[i])
			}
		}
	case *ast.DeclStmt:
		if gd, ok := s.Decl.(*ast.GenDecl); ok {
			for _, sp := range gd.Specs {
				if vs, ok := sp.(*ast.ValueSpec); ok {
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							w.expr(sc, vs.Values[i])
							w.assign(sc, n, vs.Values[i])
						} else if w.isRouterType(vs.Type) {
							sc.routers[n.Name] = ""
						}
					}
				}
			}
		}
	case *ast.BlockStmt:
		w.stmts(sc, s.List)
	case *ast.IfStmt:
		if s.Init != nil {
			w.stmt(sc, s.Init)
		}
		w.stmts(sc, s.Body.List)
		if s.Else != nil {
			w.stmt(sc, s.Else)
		}
	case *ast.ForStmt:
		w.stmts(sc, s.Body.List)
	case *ast.RangeStmt:
		w.stmts(sc, s.Body.List)
	case *ast.SwitchStmt:
		for _, c := range s.Body.List {
			w.stmts(sc, c.(*ast.CaseClause).Body)
		}
	case *ast.TypeSwitchStmt:
		for _, c := range s.Body.List {
			w.stmts(sc, c.(*ast.CaseClause).Body)
		}
	case *ast.LabeledStmt:
		w.stmt(sc, s.Stmt)
	case *ast.DeferStmt:
		w.expr(sc, s.Call)
	case *ast.GoStmt:
		w.expr(sc, s.Call)
	case *ast.ReturnStmt:
		for _, r := range s.Results {
			w.expr(sc, r)
		}
	}
}

// assign records a router or closure held by a variable or field.
func (w *goWalker) assign(sc *scope, lhs, rhs ast.Expr) {
	if fl, ok := rhs.(*ast.FuncLit); ok {
		if id, ok := lhs.(*ast.Ident); ok {
			sc.funcs[id.Name] = fl
		}
		return
	}
	p, ok := w.routerOf(sc, rhs)
	if !ok {
		return
	}
	switch l := lhs.(type) {
	case *ast.Ident:
		if l.Name != "_" {
			sc.setRouter(l.Name, p)
		}
	case *ast.SelectorExpr:
		if k := exprKey(l); k != "" {
			w.global[k] = p
		}
	}
}

// routerOf returns the prefix of a router-valued expression.
func (w *goWalker) routerOf(sc *scope, e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return w.routerOf(sc, e.X)
	case *ast.UnaryExpr:
		return w.routerOf(sc, e.X)
	case *ast.Ident:
		if p, ok := sc.router(e.Name); ok {
			return p, true
		}
		p, ok := w.global[sc.fn.pkg.dir+"."+e.Name]
		return p, ok
	case *ast.SelectorExpr:
		if k := exprKey(e); k != "" {
			if p, ok := w.global[k]; ok {
				return p, true
			}
		}
		if x, ok := e.X.(*ast.Ident); ok {
			if d := w.ix.importDir(sc.fn.file, x.Name); d != "" {
				p, ok := w.global[d+"."+e.Sel.Name]
				return p, ok
			}
		}
		return "", false
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		if x, ok := sel.X.(*ast.Ident); ok && goNewRouter[x.Name+"."+sel.Sel.Name] {
			return *sc.mount, true
		}
		switch sel.Sel.Name {
		case "Subrouter", "With", "Use", "Name":
			return w.routerOf(sc, sel.X)
		case "PathPrefix", "Group", "Route":
			if len(e.Args) == 0 {
				return "", false
			}
			if _, isFn := e.Args[0].(*ast.FuncLit); isFn { // chi Group(fn)
				return w.routerOrRoot(sc, sel.X, sel.Sel.Name)
			}
			base, ok := w.routerOrRoot(sc, sel.X, sel.Sel.Name)
			if !ok {
				return "", false
			}
			s, ok := w.str(sc, e.Args[0])
			if !ok {
				return "", false
			}
			return joinPath(base, s), true
		}
	}
	return "", false
}

// routerOrRoot is routerOf, but a receiver of a method only routers have
// (PathPrefix, HandleFunc...) is taken as a router at the root when it is
// not known: srv.Router in Mattermost, a field of a type outside the tree.
func (w *goWalker) routerOrRoot(sc *scope, x ast.Expr, method string) (string, bool) {
	if p, ok := w.routerOf(sc, x); ok {
		return p, true
	}
	switch method {
	case "PathPrefix", "HandleFunc", "Handle", "Route", "Mount":
		return "", true
	}
	return "", false
}

// expr handles route registrations, sub-router groups, mounts and calls
// into the tree's functions found in an expression.
func (w *goWalker) expr(sc *scope, e ast.Expr) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return
	}
	if w.register(sc, call) {
		return
	}
	// Calls inside the arguments (f(g(m))) are not followed; closures
	// are, through Group and calls below.
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fl := sc.closure(fn.Name); fl != nil {
			w.stmts(sc, fl.Body.List)
			return
		}
	case *ast.FuncLit:
		w.stmts(sc, fn.Body.List)
		return
	case *ast.SelectorExpr:
		if p, ok := w.routerOf(sc, fn.X); ok {
			// Some other method on a router (Use, NotFound...).
			_ = p
			return
		}
		w.expr(sc, fn.X) // chained receiver calls
	}
	w.callInto(sc, call, "")
}

// callInto walks the tree's functions a call may run, with the routers
// it passes.
func (w *goWalker) callInto(sc *scope, call *ast.CallExpr, mount string) {
	cs := w.ix.callees(sc.fn, call)
	if len(cs) == 0 {
		return
	}
	args := make([]*string, len(call.Args))
	for i, a := range call.Args {
		if p, ok := w.routerOf(sc, a); ok {
			args[i] = &p
		}
	}
	var recv *string
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if p, ok := w.routerOf(sc, sel.X); ok {
			recv = &p
		}
	}
	for _, c := range cs {
		if w.ix.routing[c.decl] {
			w.walkFunc(c, args, mount, recv)
		}
	}
}

// register handles one call if it registers routes, groups or mounts on a
// router; it reports whether it did.
func (w *goWalker) register(sc *scope, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	name := sel.Sel.Name
	// gorilla/mux chains: x.Handle(p, h).Methods("GET"),
	// x.PathPrefix(p).Handler(h).Methods("GET"), x.Path(p).HandlerFunc(h).
	if base, methods, handlers, ok := muxChain(w, sc, call); muxLink[name] && ok {
		bsel := base.Fun.(*ast.SelectorExpr)
		recvP, ok := w.routerOrRoot(sc, bsel.X, "PathPrefix")
		if !ok || len(base.Args) < 1 {
			return false
		}
		if bsel.Sel.Name == "Handle" || bsel.Sel.Name == "HandleFunc" {
			handlers = append(handlers, base.Args[1:]...)
		}
		if len(methods) == 0 {
			methods = []string{"*"}
		}
		w.emit(sc, base.Args[0], recvP, methods, handlers)
		return true
	}
	// Gitea Combo(p).Get(h).Post(h): the methods are the chain's names.
	if _, isMethod := goMethodCalls[name]; isMethod {
		if base, methods, ok := comboChain(call); ok {
			recvP, ok := w.routerOf(sc, base.Fun.(*ast.SelectorExpr).X)
			if !ok {
				return false
			}
			w.emit(sc, base.Args[0], recvP, methods, base.Args[1:])
			return true
		}
	}
	if name == "Combo" {
		return false
	}
	switch name {
	case "Handle", "HandleFunc":
		return w.handleCall(sc, call, nil)
	case "Group", "Route":
		recvP, ok := w.routerOrRoot(sc, sel.X, name)
		if !ok {
			return false
		}
		var fl *ast.FuncLit
		var pathArg ast.Expr
		for _, a := range call.Args {
			if f, ok := a.(*ast.FuncLit); ok && fl == nil {
				fl = f
			} else if pathArg == nil && fl == nil {
				pathArg = a
			}
		}
		if fl == nil {
			return false // gin/echo Group(p): an expression, see routerOf
		}
		prefix := recvP
		if pathArg != nil {
			s, ok := w.str(sc, pathArg)
			if !ok {
				w.res.unresolved += countRegistrations(fl)
				return true
			}
			prefix = joinPath(recvP, s)
		}
		inner := &scope{fn: sc.fn, routers: map[string]string{}, funcs: map[string]*ast.FuncLit{}, mount: sc.mount, parent: sc}
		// Gitea: the same router gets the group prefix while fn runs.
		if id, ok := sel.X.(*ast.Ident); ok {
			inner.routers[id.Name] = prefix
		} else if k := exprKey(sel.X); k != "" {
			old, had := w.global[k]
			w.global[k] = prefix
			defer func() {
				if had {
					w.global[k] = old
				} else {
					delete(w.global, k)
				}
			}()
		}
		// chi: the closure's router parameter.
		for _, fld := range fl.Type.Params.List {
			for _, n := range fld.Names {
				inner.routers[n.Name] = prefix
			}
		}
		w.stmts(inner, fl.Body.List)
		return true
	case "Mount":
		recvP, ok := w.routerOrRoot(sc, sel.X, name)
		if !ok || len(call.Args) < 2 {
			return false
		}
		s, ok := w.str(sc, call.Args[0])
		if !ok {
			return true
		}
		prefix := joinPath(recvP, s)
		if inner, ok := call.Args[1].(*ast.CallExpr); ok && len(w.ix.callees(sc.fn, inner)) > 0 {
			w.callInto(sc, inner, prefix)
			return true
		}
		// A router value built earlier: its routes were already
		// registered without this prefix. Not followed.
		return true
	case "Methods":
		// Gitea: m.Methods("GET,POST", pattern, h...).
		recvP, ok := w.routerOf(sc, sel.X)
		if !ok || len(call.Args) < 3 {
			return false
		}
		ms, ok := w.str(sc, call.Args[0])
		if !ok {
			return false
		}
		var methods []string
		for _, m := range strings.Split(ms, ",") {
			methods = append(methods, strings.ToUpper(strings.TrimSpace(m)))
		}
		w.emit(sc, call.Args[1], recvP, methods, call.Args[2:])
		return true
	case "Method", "MethodFunc", "Match":
		// chi: r.Method("GET", p, h); gin: r.Match([]string{"GET"}, p, h).
		recvP, ok := w.routerOf(sc, sel.X)
		if !ok || len(call.Args) < 3 {
			return false
		}
		var methods []string
		if cl, ok := call.Args[0].(*ast.CompositeLit); ok {
			for _, el := range cl.Elts {
				if m, ok := w.method(sc, el); ok {
					methods = append(methods, m)
				}
			}
		} else if m, ok := w.method(sc, call.Args[0]); ok {
			methods = []string{m}
		}
		w.emit(sc, call.Args[1], recvP, methods, call.Args[2:])
		return true
	}
	if m, ok := goMethodCalls[name]; ok {
		recvP, ok := w.routerOf(sc, sel.X)
		if !ok || len(call.Args) < 1 {
			return false
		}
		w.emit(sc, call.Args[0], recvP, []string{m}, call.Args[1:])
		return true
	}
	return false
}

// muxLink names the gorilla/mux route methods that may follow the call
// that sets a route's path.
var muxLink = map[string]bool{"Methods": true, "Name": true, "Queries": true, "Headers": true, "Schemes": true,
	"Host": true, "Handler": true, "HandlerFunc": true, "MatcherFunc": true}

// muxChain walks a gorilla/mux chain down to the call that sets the path
// (Handle, HandleFunc, Path, PathPrefix). A Path or PathPrefix chain is a
// route only with a Handler or HandlerFunc link; without one it only
// matches, for a Subrouter.
func muxChain(w *goWalker, sc *scope, call *ast.CallExpr) (base *ast.CallExpr, methods []string, handlers []ast.Expr, ok bool) {
	hasHandler := false
	for c := call; c != nil; {
		sel, isSel := c.Fun.(*ast.SelectorExpr)
		if !isSel {
			return nil, nil, nil, false
		}
		switch n := sel.Sel.Name; {
		case n == "Handle" || n == "HandleFunc":
			return c, methods, handlers, true
		case n == "Path" || n == "PathPrefix":
			return c, methods, handlers, hasHandler
		case n == "Methods":
			for _, a := range c.Args {
				if m, ok := w.method(sc, a); ok {
					methods = append(methods, m)
				}
			}
		case n == "Handler" || n == "HandlerFunc":
			hasHandler = true
			handlers = append(handlers, c.Args...)
		case !muxLink[n]:
			return nil, nil, nil, false
		}
		c, _ = sel.X.(*ast.CallExpr)
	}
	return nil, nil, nil, false
}

// handleCall registers x.Handle(p, h) / x.HandleFunc(p, h) /
// x.Path(p) with the methods its chain names (none: any method).
func (w *goWalker) handleCall(sc *scope, call *ast.CallExpr, methods []string) bool {
	sel := call.Fun.(*ast.SelectorExpr)
	if sel.Sel.Name == "Methods" || sel.Sel.Name == "Name" || sel.Sel.Name == "Queries" {
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if _, ok := inner.Fun.(*ast.SelectorExpr); ok {
				return w.handleCall(sc, inner, methods)
			}
		}
		return false
	}
	recvP, ok := w.routerOrRoot(sc, sel.X, sel.Sel.Name)
	if !ok || len(call.Args) < 1 {
		return false
	}
	if len(methods) == 0 {
		methods = []string{"*"}
	}
	w.emit(sc, call.Args[0], recvP, methods, call.Args[1:])
	return true
}

// chainMethods collects the HTTP methods of .Methods(...) calls in a
// chain.
func (w *goWalker) chainMethods(sc *scope, call *ast.CallExpr) []string {
	var out []string
	for c := call; c != nil; {
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		if sel.Sel.Name == "Methods" {
			for _, a := range c.Args {
				if m, ok := w.method(sc, a); ok {
					out = append(out, m)
				}
			}
		}
		c, _ = sel.X.(*ast.CallExpr)
	}
	return out
}

func (w *goWalker) method(sc *scope, e ast.Expr) (string, bool) {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "http" {
			m, ok := httpMethodConst[sel.Sel.Name]
			return m, ok
		}
	}
	s, ok := w.str(sc, e)
	return strings.ToUpper(s), ok
}

// comboChain recognises Gitea's m.Combo(p, mw...).Get(h).Post(h): it
// returns the Combo call and the methods of the chain.
func comboChain(call *ast.CallExpr) (*ast.CallExpr, []string, bool) {
	var methods []string
	c := call
	for {
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil, nil, false
		}
		if sel.Sel.Name == "Combo" {
			if len(c.Args) < 1 {
				return nil, nil, false
			}
			return c, methods, len(methods) > 0
		}
		m, ok := goMethodCalls[sel.Sel.Name]
		if !ok {
			return nil, nil, false
		}
		methods = append(methods, m)
		inner, ok := sel.X.(*ast.CallExpr)
		if !ok {
			return nil, nil, false
		}
		c = inner
	}
}

// emit records a route: the receiver's prefix joined with the pattern,
// when its methods include GET or any method.
func (w *goWalker) emit(sc *scope, pattern ast.Expr, prefix string, methods []string, handlers []ast.Expr) {
	get := false
	for _, m := range methods {
		if m == "GET" || m == "*" {
			get = true
		}
	}
	p, ok := w.str(sc, pattern)
	// net/http 1.22 patterns: "GET /items/{id}", "example.com/x".
	if ok {
		if i := strings.IndexByte(p, ' '); i > 0 {
			m := strings.ToUpper(p[:i])
			get = m == "GET"
			p = strings.TrimSpace(p[i+1:])
		}
	}
	if !get {
		return
	}
	if !ok {
		w.res.unresolved++
		return
	}
	paths, ok := normalizePath(joinPath(prefix, p))
	if !ok {
		w.res.unresolved++
		return
	}
	q := w.queryParams(sc, handlers)
	for _, full := range paths {
		w.res.routes = append(w.res.routes, found{kind: KindGo, path: full, query: q})
	}
}

// queryParams returns the query parameter names the route's handler
// functions read directly (r.URL.Query().Get("x"), r.FormValue("x"),
// ctx.FormString("x")...).
func (w *goWalker) queryParams(sc *scope, handlers []ast.Expr) []string {
	seen := map[string]bool{}
	var out []string
	var bodies []*ast.BlockStmt
	for _, h := range handlers {
		ast.Inspect(h, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				bodies = append(bodies, n.Body)
				return false
			case *ast.Ident, *ast.SelectorExpr:
				fake := &ast.CallExpr{Fun: n.(ast.Expr)}
				for _, f := range w.ix.callees(sc.fn, fake) {
					bodies = append(bodies, f.decl.Body)
				}
				if _, ok := n.(*ast.SelectorExpr); ok {
					return false
				}
			}
			return true
		})
	}
	for _, b := range bodies {
		ast.Inspect(b, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			isQuery := goQueryCalls[name]
			// r.URL.Query().Get("x")
			if name == "Get" {
				if inner, ok := sel.X.(*ast.CallExpr); ok {
					if isel, ok := inner.Fun.(*ast.SelectorExpr); ok && isel.Sel.Name == "Query" {
						isQuery = true
					}
				}
			}
			if !isQuery {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil && s != "" && !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// str evaluates a string expression: a literal, a constant of the tree
// (also in another package), or a + of those.
func (w *goWalker) str(sc *scope, e ast.Expr) (string, bool) {
	return w.strDepth(sc.fn.pkg, sc.fn.file, e, 0)
}

func (w *goWalker) strDepth(p *goPkg, af *ast.File, e ast.Expr, depth int) (string, bool) {
	if depth > 16 {
		return "", false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return w.strDepth(p, af, e.X, depth+1)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		a, ok := w.strDepth(p, af, e.X, depth+1)
		if !ok {
			return "", false
		}
		b, ok := w.strDepth(p, af, e.Y, depth+1)
		return a + b, ok
	case *ast.Ident:
		if v, ok := p.consts[e.Name]; ok {
			return w.strDepth(p, w.fileOf(p, v, af), v, depth+1)
		}
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			if d := w.ix.importDir(af, x.Name); d != "" {
				if op := w.ix.pkgs[d]; op != nil {
					if v, ok := op.consts[e.Sel.Name]; ok {
						return w.strDepth(op, w.fileOf(op, v, nil), v, depth+1)
					}
				}
			}
		}
	}
	return "", false
}

// fileOf returns the file of p that holds node n, for its imports.
func (w *goWalker) fileOf(p *goPkg, n ast.Node, fallback *ast.File) *ast.File {
	for _, f := range p.files {
		if f.Pos() <= n.Pos() && n.End() <= f.End() {
			return f
		}
	}
	return fallback
}

// countRegistrations counts route calls inside a group whose prefix is
// not known, so they are reported as unresolved.
func countRegistrations(fl *ast.FuncLit) int {
	n := 0
	ast.Inspect(fl.Body, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
				if m, ok := goMethodCalls[sel.Sel.Name]; ok && (m == "GET" || m == "*") {
					n++
				}
			}
		}
		return true
	})
	return n
}

func exprKey(e ast.Expr) string {
	var b strings.Builder
	var walk func(ast.Expr) bool
	walk = func(e ast.Expr) bool {
		switch e := e.(type) {
		case *ast.Ident:
			b.WriteString(e.Name)
			return true
		case *ast.SelectorExpr:
			if !walk(e.X) {
				return false
			}
			b.WriteString("." + e.Sel.Name)
			return true
		case *ast.StarExpr:
			return walk(e.X)
		case *ast.ParenExpr:
			return walk(e.X)
		}
		return false
	}
	if !walk(e) {
		return ""
	}
	return b.String()
}

// joinPath joins a prefix and a pattern the way Gitea's router does
// (leading slash, no trailing slash).
func joinPath(prefix, p string) string {
	return prefix + p
}
