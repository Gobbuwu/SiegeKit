package coderoutes

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/authz"
)

// tree writes files under a temporary directory and returns it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// paths returns each route as "path q1,q2" (query parameters sent), sorted.
func paths(rs []authz.SpecRoute) []string {
	var out []string
	for _, r := range rs {
		var q []string
		for _, p := range r.Params {
			if p.In == "query" {
				q = append(q, p.Name)
			}
		}
		s := r.Path
		if len(q) > 0 {
			s += " " + strings.Join(q, ",")
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func mustFrom(t *testing.T, dir string) Result {
	t.Helper()
	r, err := FromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("routes:\n got  %q\n want %q", got, want)
	}
}

// Mattermost's shape: routers in struct fields, prefixes from a constant
// in another module of the tree, routes registered in methods called
// from Init, a regex in a path parameter, Methods on the chain, and a
// PathPrefix route with a Handler.
func TestGorillaFieldsAndConstants(t *testing.T) {
	dir := tree(t, map[string]string{
		"public/go.mod":         "module example.com/app/public\n",
		"public/model/const.go": "package model\n\nconst (\n\tAPIURLSuffixV4 = \"/api/v4\"\n\tAPIURLSuffix = APIURLSuffixV4\n)\n",
		"server/go.mod":         "module example.com/app/server\n",
		"server/api4/api.go": `package api4

import (
	"net/http"

	"github.com/gorilla/mux"
	"example.com/app/public/model"
)

type Routes struct {
	Root, APIRoot, Channels, Channel, Groups *mux.Router
}

type API struct{ BaseRoutes *Routes }

type Server struct{ Router *mux.Router }

func Init(srv *Server) {
	api := &API{BaseRoutes: &Routes{}}
	api.BaseRoutes.Root = srv.Router
	api.BaseRoutes.APIRoot = srv.Router.PathPrefix(model.APIURLSuffix).Subrouter()
	api.BaseRoutes.Channels = api.BaseRoutes.APIRoot.PathPrefix("/channels").Subrouter()
	api.BaseRoutes.Channel = api.BaseRoutes.Channels.PathPrefix("/{channel_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.Groups = api.BaseRoutes.APIRoot.PathPrefix("/groups").Subrouter()
	api.InitChannel()
	srv.Router.PathPrefix("/.well-known/x").Handler(http.HandlerFunc(meta)).Methods(http.MethodGet)
}

func meta(w http.ResponseWriter, r *http.Request) {}
`,
		"server/api4/channel.go": `package api4

import "net/http"

func (api *API) InitChannel() {
	api.BaseRoutes.Channel.Handle("", api.APISessionRequired(getChannel)).Methods(http.MethodGet)
	api.BaseRoutes.Channel.Handle("", api.APISessionRequired(deleteChannel)).Methods(http.MethodDelete)
	api.BaseRoutes.Channel.Handle("/posts", api.APISessionRequired(getPosts)).Methods("GET", "HEAD")
	api.BaseRoutes.Groups.Handle("/{group_id:[A-Za-z0-9]+}/{syncable_type:teams|channels}", api.APISessionRequired(getPosts)).Methods(http.MethodGet)
}

func (api *API) APISessionRequired(h func(w http.ResponseWriter, r *http.Request)) http.Handler { return nil }

func getChannel(w http.ResponseWriter, r *http.Request)    {}
func deleteChannel(w http.ResponseWriter, r *http.Request) {}
func getPosts(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	_ = r.URL.Query().Get("page")
	_ = r.FormValue("before_post_id")
	_ = since
}
`,
		"server/api4/channel_test.go": "package api4\n\nfunc init() { var r *mux.Router; r.Handle(\"/test-only\", nil) }\n",
	})
	r := mustFrom(t, dir)
	eq(t, paths(r.Routes), []string{
		"/.well-known/x",
		"/api/v4/channels/{channel_id}",
		"/api/v4/channels/{channel_id}/posts before_post_id,since",
		"/api/v4/groups/{group_id}/channels before_post_id,since",
		"/api/v4/groups/{group_id}/teams before_post_id,since",
	})
	if r.Found[KindGo] != 5 || r.Unresolved != 0 {
		t.Errorf("found %v, unresolved %d", r.Found, r.Unresolved)
	}
	// since is sent with the earliest date; the ID-named filter only when
	// the recording has one; page is left out.
	for _, rt := range r.Routes {
		if rt.Path != "/api/v4/channels/{channel_id}/posts" {
			continue
		}
		for _, p := range rt.Params {
			switch p.Name {
			case "since":
				if !p.Required || p.Fill {
					t.Errorf("since: %+v", p)
				}
			case "before_post_id":
				if p.Required || !p.Fill {
					t.Errorf("before_post_id: %+v", p)
				}
			case "channel_id":
				if p.In != "path" || !p.Required {
					t.Errorf("channel_id: %+v", p)
				}
			}
		}
		if !rt.FromCode {
			t.Error("FromCode not set")
		}
	}
}

// Gitea's shape: Group(prefix, func(){...}) changes the prefix of the same
// router while the closure runs, closures held in variables, Combo, Methods
// with a method list, Mount of a function's router, wildcards counted.
func TestGiteaGroupsAndMount(t *testing.T) {
	dir := tree(t, map[string]string{
		"go.mod": "module example.com/gt\n",
		"routers/init.go": `package routers

import (
	apiv1 "example.com/gt/routers/api/v1"
	"example.com/gt/modules/web"
)

func NormalRoutes() *web.Router {
	r := web.NewRouter()
	r.Mount("/api/v1", apiv1.Routes())
	return r
}
`,
		"modules/web/router.go": "package web\n\ntype Router struct{}\n\nfunc NewRouter() *Router { return &Router{} }\n",
		"routers/api/v1/api.go": `package v1

import "example.com/gt/modules/web"

func Routes() *web.Router {
	m := web.NewRouter()
	m.Get("/version", version)
	addRepo := func() {
		m.Get("/issues/{index}", issue)
		m.Get("/raw/*", raw)
	}
	m.Group("/repos", func() {
		m.Get("/search", search)
		m.Group("/{username}/{reponame}", func() {
			addRepo()
			m.Combo("/milestones/{id}").Get(milestone).Patch(milestone)
			m.Combo("/labels").Post(label)
			m.Methods("HEAD,GET", "/archive/{archive}", archive)
		})
	})
	m.Post("/markdown", markdown)
	return m
}

func version()   {}
func issue()     {}
func raw()       {}
func milestone() {}
func label()     {}
func archive()   {}
func markdown()  {}
func search(ctx *Context) {
	_ = ctx.FormString("q")
	_ = ctx.FormInt64("uid")
}

type Context struct{}

func (c *Context) FormString(string) string { return "" }
func (c *Context) FormInt64(string) int64   { return 0 }
`,
	})
	r := mustFrom(t, dir)
	eq(t, paths(r.Routes), []string{
		"/api/v1/repos/search uid",
		"/api/v1/repos/{username}/{reponame}/archive/{archive}",
		"/api/v1/repos/{username}/{reponame}/issues/{index}",
		"/api/v1/repos/{username}/{reponame}/milestones/{id}",
		"/api/v1/version",
	})
	if r.Unresolved != 1 { // /raw/*
		t.Errorf("unresolved %d, want 1", r.Unresolved)
	}
}

// chi, gin, echo and net/http 1.22 patterns.
func TestOtherGoRouters(t *testing.T) {
	dir := tree(t, map[string]string{
		"go.mod": "module example.com/x\n",
		"main.go": `package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
)

func main() {
	r := chi.NewRouter()
	r.Route("/api", func(r chi.Router) {
		r.Get("/items/{itemID}", nil)
		r.Post("/items", nil)
		r.Method("GET", "/m/{id}", nil)
		r.Group(func(r chi.Router) {
			r.Get("/inner", nil)
		})
	})
	g := gin.Default()
	v1 := g.Group("/v1")
	v1.GET("/users/:id", nil)
	v1.DELETE("/users/:id", nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /posts/{id}", nil)
	mux.HandleFunc("POST /posts", nil)
	mux.HandleFunc("/any", nil)
	var cache map[string]string
	_ = cache
	get("/not-a-route")
	// Navidrome: a helper given the prefix as a string, and one building
	// the path from its string parameter.
	n := &api{}
	r.Group(func(r chi.Router) {
		n.R(r, "/song")
		n.R(r, "/album")
		h(r, "getSong")
	})
	n.R(r, unknownPrefix())
}

func get(string) {}

type api struct{}

func (n *api) R(r chi.Router, pathPrefix string) {
	r.Route(pathPrefix, func(r chi.Router) {
		r.Get("/", nil)
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", nil)
		})
	})
}

func h(r chi.Router, path string) {
	r.HandleFunc("/"+path, nil)
	r.HandleFunc("/"+path+".view", nil)
}

func unknownPrefix() string { return "/x" }
`,
	})
	r := mustFrom(t, dir)
	eq(t, paths(r.Routes), []string{
		"/album",
		"/album/{id}",
		"/any",
		"/api/inner",
		"/api/items/{itemID}",
		"/api/m/{id}",
		"/getSong",
		"/getSong.view",
		"/posts/{id}",
		"/song",
		"/song/{id}",
		"/v1/users/{id}",
	})
	if r.Unresolved != 2 { // n.R(r, unknownPrefix()): its 2 GET routes
		t.Errorf("unresolved %d, want 2", r.Unresolved)
	}
}

// Rocket.Chat 6 and 8 shapes, Express, and code that only looks like
// routes (comments, strings, regex literals, templates, other objects).
func TestJavaScriptRoutes(t *testing.T) {
	dir := tree(t, map[string]string{
		"apps/meteor/app/api/server/v1/chat.ts": `
import { API } from '../api';

API.v1.addRoute(
	'chat.getDeletedMessages',
	{ authRequired: true },
	{
		async get() {
			const { roomId, since } = this.queryParams;
			const { offset, count } = await getPaginationItems(this.queryParams);
			return API.v1.success({});
		},
	},
);

API.v1.addRoute(['dm.history', 'im.history'], { authRequired: true }, {
	async get() {
		const { roomId = '', latest } = this.queryParams as { roomId: string; latest?: string };
		return API.v1.success();
	},
	async post() {},
});

API.v1.addRoute('chat.update', { authRequired: true }, { async post() { const { msgId } = this.bodyParams; } });

API.v1.addRoute('rooms.upload/:rid', { authRequired: true }, { async post() {} });

API.v1.addRoute('rooms.media/:rid', { authRequired: true }, {
	get: {
		action() { return this.queryParams.fileId; },
	},
});

// API.v1.addRoute('commented.out', {}, { get() {} });
const s = "API.v1.addRoute('in.a.string', {}, { get() {} })";
const re = /API.v1.addRoute\('in.a.regex'/g;
const tpl = ` + "`API.v1.addRoute('in.a.template', {}, { get() {} }) ${x}`" + `;
`,
		"apps/meteor/server/api/v1/chat.ts": `
const chatEndpoints = API.v1
	.post('chat.delete', { authRequired: true }, async function action() {})
	.get<Foo>(
		'chat.syncMessages',
		{ authRequired: true, query: isProps },
		async function action() {
			const { roomId, lastUpdate, type } = this.queryParams;
			return API.v1.success();
		},
	)
	.get('chat.getMessage', { authRequired: true }, async function action() {
		if (!this.queryParams.msgId) { throw new Error('x'); }
	});
API.default.get('info', {}, async function action() {});
settings.get('Accounts_Default', true);
`,
		"server.ts": `
app.get('/rest/products/:id/reviews', (req, res) => { const q = req.query.q; });
app.post('/rest/user/login', login);
router.route('/api/Addresss/:id').get(byId).put(update);
app.get('/rest/track-order/:id(\\d+)', track);
app.get(` + "`/rest/${version}/x`" + `, h);
const { rows } = await db.query('SELECT 1');
axios.get('https://example.com/x', {});
`,
		"node_modules/express/lib/router.js":  "app.get('/from-a-dependency', h)",
		"apps/meteor/tests/end-to-end/api.ts": "API.v1.addRoute('from.a.test', {}, { get() {} })",
		"apps/meteor/client/lib/presence.ts":  "await sdk.rest.get('/v1/users.presence', params);",
	})
	r := mustFrom(t, dir)
	eq(t, paths(r.Routes), []string{
		"/api/Addresss/{id}",
		"/api/info",
		"/api/v1/chat.getDeletedMessages roomId,since",
		"/api/v1/chat.getMessage msgId",
		"/api/v1/chat.syncMessages roomId",
		"/api/v1/dm.history roomId",
		"/api/v1/im.history roomId",
		"/api/v1/rooms.media/{rid} fileId",
		"/rest/products/{id}/reviews",
	})
	if r.Found[KindRocketChat] != 7 || r.Found[KindExpress] != 2 {
		t.Errorf("found %v", r.Found)
	}
	if r.Unresolved != 2 { // the :id(\d+) route and the template path
		t.Errorf("unresolved %d, want 2", r.Unresolved)
	}
}

func TestNormalizePath(t *testing.T) {
	for in, want := range map[string]string{
		"/a/{id:[0-9]{3}}/b/": "/a/{id}/b",
		"a//b":                "/a/b",
		"/users/:id/x":        "/users/{id}/x",
		"/x/{t:issues|pulls}": "/x/issues /x/pulls",
		"/":                   "/",
		"/a/*":                "",
		"/{path...}":          "",
		"/a/{":                "",
		"/a/:id?":             "",
		"/a?b=1":              "",
	} {
		got, ok := normalizePath(in)
		if strings.Join(got, " ") != want || ok != (want != "") {
			t.Errorf("normalizePath(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

func TestLimitsAndErrors(t *testing.T) {
	if _, err := FromPath(tree(t, map[string]string{"README.md": "# x"})); err != ErrNoSource {
		t.Errorf("no source: %v", err)
	}
	dir := tree(t, map[string]string{"a.go": "package main\nfunc main() {", "b.js": "app.get('/ok', h)"})
	big := filepath.Join(dir, "big.js")
	if err := os.WriteFile(big, make([]byte, MaxFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symbolic link out of the tree is not followed.
	outside := tree(t, map[string]string{"evil.js": "app.get('/outside', h)"})
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	r := mustFrom(t, dir)
	if r.Unparsed != 1 || r.TooBig != 1 || r.Files != 2 {
		t.Errorf("unparsed %d, too big %d, files %d", r.Unparsed, r.TooBig, r.Files)
	}
	eq(t, paths(r.Routes), []string{"/ok"})
	// One file works too.
	r = mustFrom(t, filepath.Join(dir, "b.js"))
	eq(t, paths(r.Routes), []string{"/ok"})
}

// Calls that recurse into each other, and code built to fan out, end.
func TestGoRecursionEnds(t *testing.T) {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"github.com/go-chi/chi/v5\"\n\nfunc a(r chi.Router) { r.Get(\"/a\", nil); b(r); a(r) }\nfunc b(r chi.Router) { r.Get(\"/b\", nil); a(r) }\n")
	b.WriteString("func main() { r := chi.NewRouter(); a(r)\n")
	for i := 0; i < 50; i++ {
		b.WriteString("\tf0(r)\n")
	}
	b.WriteString("}\n")
	for i := 0; i < 30; i++ {
		b.WriteString("func f" + itoa(i) + "(r chi.Router) { f" + itoa(i+1) + "(r); f" + itoa(i+1) + "(r) }\n")
	}
	b.WriteString("func f30(r chi.Router) { r.Get(\"/leaf\", nil) }\n")
	r := mustFrom(t, tree(t, map[string]string{"go.mod": "module m\n", "main.go": b.String()}))
	eq(t, paths(r.Routes), []string{"/a", "/b", "/leaf"})
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+i/10)) + string(rune('0'+i%10)))
}

func FuzzTokenizeJS(f *testing.F) {
	for _, s := range []string{"API.v1.addRoute('a', {}, { get() { const {x} = this.queryParams } })", "`${`${a}`}`", "/[/]/.test(x)", "a / b / c", "'unterminated", "/* x", "x?.y ?? z", "app.route('/x').get(h)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		toks := tokenizeJS([]byte(s))
		var res jsResult
		scanRocketChat(toks, &res)
		scanExpress(toks, &res)
	})
}

func FuzzGoRoutes(f *testing.F) {
	f.Add("package p\nimport \"github.com/go-chi/chi/v5\"\nfunc F(r chi.Router) { r.Route(\"/a\", func(r chi.Router) { r.Get(\"/b\", h) }) }")
	f.Add("package p\nfunc F() { m := web.NewRouter(); m.Group(\"/x\", func() { m.Combo(\"/y\").Get(h) }) }")
	f.Fuzz(func(t *testing.T, s string) {
		goRoutes([]srcFile{{path: "/x/a.go", data: []byte(s)}}, "/x")
	})
}

// The server bundles Rocket.Chat's images ship (app.js), as transpiled:
// 6.13.1 wraps handlers in Promise.asyncApply; 8.9.1 keeps the chain.
func TestRocketChatBundleShapes(t *testing.T) {
	dir := tree(t, map[string]string{
		"bundle/programs/server/app/app.js": `
module.link("../api", { API(v) { API = v; } }, 0);
API.v1.addRoute('chat.getDeletedMessages', {
  authRequired: true
}, {
  get() {
    return Promise.asyncApply(() => {
      const {
        roomId,
        since
      } = this.queryParams;
      return API.v1.success({});
    });
  }
});
const chatEndpoints = API.v1.post('chat.delete', {
  authRequired: true
}, async function action() {}).get('chat.getMessage', {
  authRequired: true
}, async function action() {
  const { msgId } = this.queryParams;
});
`,
	})
	eq(t, paths(mustFrom(t, dir).Routes), []string{
		"/api/v1/chat.getDeletedMessages roomId,since",
		"/api/v1/chat.getMessage msgId",
	})
}
