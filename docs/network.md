# Network: proxies, TLS inspection, registry limits and Go modules

Scans of a directory run with no network. These steps do use it (ADR 0014, 0016, 0024, 0066):

| Step | Who connects | Settings it uses |
|---|---|---|
| Tool images (`docker pull` / `podman pull`) | your container engine | the engine's own proxy, mirror and sign-in settings |
| Pinned files (Nuclei, ffuf, wordlists) | SiegeKit, on your machine | `HTTPS_PROXY` and your system's certificates |
| Tool data (`siegekit update`, Trivy's database) | a container with network and none of your files | `--ca-file`, `--proxy` |
| Go modules for gosec (asked in the install question) | a container with network and only copies of your `go.mod`, `go.sum`, `go.work` and `go.work.sum` files | `--ca-file`, `--proxy` |

## A proxy or TLS inspection (`--ca-file`, `--proxy`)

Behind a proxy that inspects TLS, the two network containers fail with `x509: certificate signed by unknown authority`; on a network whose only way out is a proxy, they cannot connect at all. Pass the proxy's CA certificate and, if needed, the proxy itself to `siegekit scan DIR` or `siegekit update`:

```sh
siegekit update --ca-file /path/to/company-ca.pem --proxy http://proxy.example.com:3128
```

Or set them once in your shell profile or CI settings, which SiegeKit reads when the flags are not given:

```sh
export SIEGEKIT_CA_FILE=/path/to/company-ca.pem
export SIEGEKIT_PROXY=http://proxy.example.com:3128
```

- The CA file is a PEM file of one or more certificates. It is mounted read-only and named by `SSL_CERT_FILE`; the images' own certificates still count, so public sites keep working (measured with both pinned images).
- The proxy is `http://` or `https://` with a host and port. A proxy URL with a user name or password is refused: it would be visible in the container's environment.
- The proxy must be reachable from a container. On Linux, a proxy listening only on 127.0.0.1 is not; give an address on another interface. Under Colima on macOS, `host.docker.internal` reaches the Mac's own 127.0.0.1 (measured).
- On macOS, a CA installed in the Keychain is in no file a container can read. Export it to a file first, for example `security find-certificate -a -p -c "Company CA" /Library/Keychains/System.keychain > company-ca.pem`.
- Scan containers never get these settings: they have no network.
- SiegeKit does not read `HTTPS_PROXY` or `SSL_CERT_FILE` from your environment for containers: settings meant for other programs would reach them without you choosing it (ADR 0066).

Image downloads are made by your container engine, which has its own proxy settings: Docker's daemon proxy configuration, or for Podman the `env` list in the `[engine]` table of `containers.conf`. SiegeKit has not measured these; see the engines' documentation.

## Docker Hub's download limit (429 Too Many Requests)

Docker Hub limits downloads: 100 per hour per IP address without signing in, 200 per hour per account when signed in (headers read on 2026-11-24). On a shared address, such as a CI runner or a cloud machine, other users can use up the limit (one runner had 0 left). When a download fails this way, SiegeKit says so and how to fix it. Either:

**Sign in.** SiegeKit's downloads use the sign-in your engine stores (measured on both engines):

```sh
docker login        # or: podman login docker.io
```

**Or use a registry mirror** set in your engine. SiegeKit keeps using the original `docker.io` names and pinned digests; the engine fetches the same image, checked by its digest, from the mirror (measured with `https://mirror.gcr.io`, Google's public mirror of Docker Hub):

- Docker, in `/etc/docker/daemon.json` (then restart the daemon):

  ```json
  { "registry-mirrors": ["https://mirror.gcr.io"] }
  ```

- Podman, in `/etc/containers/registries.conf` or `~/.config/containers/registries.conf`:

  ```toml
  [[registry]]
  prefix = "docker.io"
  location = "docker.io"

  [[registry.mirror]]
  location = "mirror.gcr.io"
  ```

- Colima on macOS, in `~/.colima/default/colima.yaml` (then `colima restart`):

  ```yaml
  docker:
    registry-mirrors:
      - https://mirror.gcr.io
  ```

Images on `ghcr.io` (gosec, bandit) have no public mirror that SiegeKit knows of; a limit there has not been seen.

## Go modules for gosec

gosec needs a Go app's modules to check it fully; without them it skips the packages that import them and the report names those packages (ADR 0040). The install question offers to download them:

```
Go modules for gosec: 41 modules named in your go.mod files, from proxy.golang.org, which sees their names and versions
```

- `go mod download` runs in gosec's pinned image, with network, in each folder with a `go.mod`. The container gets copies of the module files only, never your code. Settings: `GOPROXY=https://proxy.golang.org` (no direct downloads from source hosts), `GOVCS=*:off` (no git or other version control), `GOTOOLCHAIN=local` (no Go toolchain downloads), and Go's checksum database checks every module that `go.sum` does not list.
- What leaves your machine: the names and versions of the modules, sent to proxy.golang.org (run by Google), and checksum lookups at sum.golang.org for modules missing from `go.sum`.
- Private modules: SiegeKit passes your `GOPRIVATE` and `GONOPROXY` (from the environment, or from Go's settings file written by `go env -w`) to the download. Go then never asks the proxy for matching modules, and cannot fetch them another way, so their packages are listed as not checked.
- `--yes` accepts the download; `--no-install` and runs with no terminal decline it. Declined or failed, gosec still runs and names the packages it could not load, with the reason.
- The modules are kept in one shared cache, `~/.local/share/siegekit/data/gomod`, and later scans reuse it: a check with no network finds when every module is already there, and nothing is asked. Reports give the cache's size. To remove it, Go makes its files read-only, and with rootless Podman they belong to a user of your Podman namespace:

  ```sh
  chmod -R u+w ~/.local/share/siegekit/data/gomod && rm -rf ~/.local/share/siegekit/data/gomod   # Docker
  podman unshare rm -rf ~/.local/share/siegekit/data/gomod                                      # rootless Podman
  ```

- gosec builds in a scratch folder on disk, `~/.local/share/siegekit/data/scratch`, deleted after each run. It needs about 1 GB for caddy (872 MiB), 3 GB for consul and 7.4 GB for grafana, measured; the module cache for those apps holds 0.9, 1.7 and up to 6.5 GB. It is not in the system's temporary folder, which can be in memory and would then count against gosec's memory limit (measured).
