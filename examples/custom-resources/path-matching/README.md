# Path Matching

In this example we demonstrate the NGINX location matching hierarchy using the
[VirtualServer and VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/)
resources. The example shows all five path matching types supported by the VirtualServer resource and how NGINX
prioritizes them when multiple locations could match a request.

No application deployment is required. Each route uses an
[ActionReturn](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#actionreturn)
directive that responds with the match type, path directive, and request URI, so you can observe which location handles
each request.

## NGINX Location Matching Algorithm

NGINX evaluates locations in the following order:

1. **Exact match (`=`)** -- If the request URI matches a location with the `=` modifier exactly, NGINX uses that
   location immediately and stops searching.
2. **Prefix match evaluation** -- NGINX checks all prefix locations (`/path` and `^~ /path`) and remembers the longest
   match.
   - If the longest matching prefix has the `^~` modifier, NGINX uses that location and stops searching. Regex locations
     are not evaluated.
   - Otherwise, NGINX remembers this prefix match and continues to regex evaluation.
3. **Regex match (`~` and `~*`)** -- NGINX evaluates regex locations in the order they appear in the configuration.
   The first matching regex wins.
4. **Prefix fallback** -- If no regex matched, NGINX uses the longest matching prefix location remembered from step 2.

## Prerequisites

1. Follow the [installation](https://docs.nginx.com/nginx-ingress-controller/install/manifests)
   instructions to deploy the Ingress Controller with custom resources enabled.
1. Save the public IP address of the Ingress Controller into a shell variable:

    ```console
    IC_IP=XXX.YYY.ZZZ.III
    ```

1. Save the HTTP port of the Ingress Controller into a shell variable:

    ```console
    IC_HTTP_PORT=<port number>
    ```

## Step 1 - Deploy the Path Matching VirtualServer

Create the VirtualServer resource:

```console
kubectl apply -f path-matching-virtual-server.yaml
```

Check that the configuration has been successfully applied by inspecting the events of the VirtualServer:

```console
kubectl describe virtualserver path-matching
```

```text
. . .
Events:
  Type    Reason          Age   From                      Message
  ----    ------          ----  ----                      -------
  Normal  AddedOrUpdated  7s    nginx-ingress-controller  Configuration for default/path-matching was added or updated
```

## Step 2 - Test the Path Matching Hierarchy

The VirtualServer defines five routes using all five path matching types:

| Path Directive | Match Type | NGINX Location Directive |
| --- | --- | --- |
| `=/images/logo.jpg` | Exact match | `location = /images/logo.jpg` |
| `^~/images/static/` | Longest prefix match | `location ^~ /images/static/` |
| `~ \.jpg$` | Case-sensitive regex | `location ~ "\.jpg$"` |
| `~* \.png$` | Case-insensitive regex | `location ~* "\.png$"` |
| `/images/` | Prefix match | `location /images/` |

Access the application using curl. We'll use curl's `--resolve` option to set the IP address and HTTP port of the
Ingress Controller to the domain name of the application:

**Exact match wins over regex and prefix:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/logo.jpg
```

```text
EXACT MATCH (=)
Path Directive: =/images/logo.jpg
Request URI:    /images/logo.jpg
Exact match has the highest priority and stops all further searching.
```

Even though `~ \.jpg$` and `/images/` could both match this URI, the exact match `=/images/logo.jpg` wins because exact
match has the highest priority.

**Longest prefix match beats regex:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/static/photo.jpg
```

```text
LONGEST PREFIX MATCH (^~)
Path Directive: ^~/images/static/
Request URI:    /images/static/photo.jpg
The ^~ modifier stops NGINX from checking regex locations when this prefix matches.
```

The `^~` prefix match prevents NGINX from evaluating regex locations. Even though `~ \.jpg$` would match this URI, the
`^~` modifier on `/images/static/` takes priority.

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/static/icon.png
```

```text
LONGEST PREFIX MATCH (^~)
Path Directive: ^~/images/static/
Request URI:    /images/static/icon.png
The ^~ modifier stops NGINX from checking regex locations when this prefix matches.
```

Similarly, `~* \.png$` could match this URI, but `^~` prevents regex evaluation.

**Regex beats regular prefix:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/photo.jpg
```

```text
CASE-SENSITIVE REGEX MATCH (~)
Path Directive: ~ \.jpg
Request URI:    /images/photo.jpg
Regex match wins over a regular prefix but not over = or ^~ matches.
```

The `/images/` prefix matches this URI, but since it does not have the `^~` modifier, NGINX continues to evaluate regex
locations. The `~ \.jpg$` regex matches and wins.

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/photo.png
```

```text
CASE-INSENSITIVE REGEX MATCH (~*)
Path Directive: ~* \.png
Request URI:    /images/photo.png
Case-insensitive regex matches regardless of letter case (.png and .PNG both match).
```

**Case sensitivity contrast:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/photo.PNG
```

```text
CASE-INSENSITIVE REGEX MATCH (~*)
Path Directive: ~* \.png
Request URI:    /images/photo.PNG
Case-insensitive regex matches regardless of letter case (.png and .PNG both match).
```

The `~*` (case-insensitive) regex matches `.PNG` because it ignores letter case.

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/photo.JPG
```

```text
PREFIX MATCH
Path Directive: /images/
Request URI:    /images/photo.JPG
Standard prefix match has the lowest priority. This is the fallback when no other match wins.
```

The `~` (case-sensitive) regex `\.jpg$` does not match `.JPG`. With no regex match, NGINX falls back to the longest
matching prefix location `/images/`.

**Prefix as fallback:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/images/photo.gif
```

```text
PREFIX MATCH
Path Directive: /images/
Request URI:    /images/photo.gif
Standard prefix match has the lowest priority. This is the fallback when no other match wins.
```

No regex matches `.gif`, so NGINX uses the prefix fallback.

**Regex matches anywhere in the URI:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/other/photo.jpg
```

```text
CASE-SENSITIVE REGEX MATCH (~)
Path Directive: ~ \.jpg
Request URI:    /other/photo.jpg
Regex match wins over a regular prefix but not over = or ^~ matches.
```

Regex locations are not restricted to a specific path prefix. The `~ \.jpg$` pattern matches any URI ending in `.jpg`,
regardless of the directory.

**No match returns 404:**

```console
curl --resolve path-matching.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching.example.com:$IC_HTTP_PORT/other/page.html
```

```text
<html>
<head><title>404 Not Found</title></head>
...
```

No location matches this URI. The prefix `/images/` does not match `/other/`, and no regex matches `.html`.

### Summary

| Request URI | Could Match | Winner | Reason |
| --- | --- | --- | --- |
| `/images/logo.jpg` | `=`, `~`, `/` | `=/images/logo.jpg` | Exact match always wins |
| `/images/static/photo.jpg` | `^~`, `~`, `/` | `^~/images/static/` | `^~` blocks regex evaluation |
| `/images/static/icon.png` | `^~`, `~*`, `/` | `^~/images/static/` | `^~` blocks regex evaluation |
| `/images/photo.jpg` | `~`, `/` | `~ \.jpg$` | Regex beats regular prefix |
| `/images/photo.png` | `~*`, `/` | `~* \.png$` | Regex beats regular prefix |
| `/images/photo.PNG` | `~*`, `/` | `~* \.png$` | `~*` is case-insensitive |
| `/images/photo.JPG` | `/` | `/images/` | `~` is case-sensitive, `.JPG` does not match |
| `/images/photo.gif` | `/` | `/images/` | No regex matches `.gif` |
| `/other/photo.jpg` | `~` | `~ \.jpg$` | Regex has no path prefix requirement |
| `/other/photo.png` | `~*` | `~* \.png$` | Regex has no path prefix requirement |
| `/other/page.html` | none | 404 | No location matches |

## Step 3 - Deploy the Subroute Examples

This step demonstrates how
[VirtualServerRoute](https://docs.nginx.com/nginx-ingress-controller/configuration/virtualserver-and-virtualserverroute-resources/#virtualserverroute-specification)
subroutes interact with path delegation.

When a VirtualServer route delegates to a VirtualServerRoute, the parent route's path does not create an NGINX location
block. Only the subroute paths become NGINX locations. If a request matches the parent path prefix but none of the
subroute paths, no location handles it and NGINX returns 404.

1. Create the VirtualServerRoute for prefix subroutes:

    ```console
    kubectl apply -f prefix-virtual-server-route.yaml
    ```

1. Create the VirtualServerRoute for longest prefix subroutes:

    ```console
    kubectl apply -f longest-prefix-virtual-server-route.yaml
    ```

1. Create the VirtualServer that delegates to the VirtualServerRoutes:

    ```console
    kubectl apply -f path-matching-with-subroutes-virtual-server.yaml
    ```

1. Check that the configuration has been successfully applied:

    ```console
    kubectl describe virtualserver path-matching-vsr
    ```

    ```text
    . . .
    Events:
      Type    Reason          Age   From                      Message
      ----    ------          ----  ----                      -------
      Normal  AddedOrUpdated  7s    nginx-ingress-controller  Configuration for default/path-matching-vsr was added or updated
    ```

## Step 4 - Test the Subroute Configuration

The VirtualServer delegates two path prefixes to VirtualServerRoutes:

- `/images/` delegates to `prefix-routes`, which defines subroutes `/images/thumbnails/` and `/images/originals/`.
- `^~/static/` delegates to `longest-prefix-routes`, which defines subroutes `^~/static/css/` and `^~/static/js/`.

**Subroute matches:**

```console
curl --resolve path-matching-vsr.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching-vsr.example.com:$IC_HTTP_PORT/images/thumbnails/cat.jpg
```

```text
PREFIX SUBROUTE MATCH
Path Directive:      /images/thumbnails/
Request URI:         /images/thumbnails/cat.jpg
VirtualServerRoute:  prefix-routes
Matched a subroute under the /images/ parent route delegation.
```

```console
curl --resolve path-matching-vsr.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching-vsr.example.com:$IC_HTTP_PORT/images/originals/cat.jpg
```

```text
PREFIX SUBROUTE MATCH
Path Directive:      /images/originals/
Request URI:         /images/originals/cat.jpg
VirtualServerRoute:  prefix-routes
Matched a subroute under the /images/ parent route delegation.
```

```console
curl --resolve path-matching-vsr.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching-vsr.example.com:$IC_HTTP_PORT/static/css/main.css
```

```text
LONGEST PREFIX SUBROUTE MATCH (^~)
Path Directive:      ^~/static/css/
Request URI:         /static/css/main.css
VirtualServerRoute:  longest-prefix-routes
Subroutes under a ^~ parent must also use the ^~ modifier.
```

```console
curl --resolve path-matching-vsr.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching-vsr.example.com:$IC_HTTP_PORT/static/js/app.js
```

```text
LONGEST PREFIX SUBROUTE MATCH (^~)
Path Directive:      ^~/static/js/
Request URI:         /static/js/app.js
VirtualServerRoute:  longest-prefix-routes
Subroutes under a ^~ parent must also use the ^~ modifier.
```

**Parent delegation does not create a fallback location:**

```console
curl --resolve path-matching-vsr.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching-vsr.example.com:$IC_HTTP_PORT/images/other.jpg
```

```text
<html>
<head><title>404 Not Found</title></head>
...
```

Even though the parent VirtualServer route has path `/images/`, this does not create an NGINX location block. The parent
path is only a delegation directive and a validation constraint that requires subroute paths to start with `/images/`.
Only the subroute paths (`/images/thumbnails/` and `/images/originals/`) become NGINX locations. Since
`/images/other.jpg` does not match either subroute prefix, no location handles the request and NGINX returns 404.

```console
curl --resolve path-matching-vsr.example.com:$IC_HTTP_PORT:$IC_IP http://path-matching-vsr.example.com:$IC_HTTP_PORT/static/fonts/bold.woff
```

```text
<html>
<head><title>404 Not Found</title></head>
...
```

Same behavior for the `^~` parent. Only `^~/static/css/` and `^~/static/js/` locations exist. There is no
`^~/static/` fallback location.

### Subroute Test Summary

| Request URI | Winner | Reason |
| --- | --- | --- |
| `/images/thumbnails/cat.jpg` | `/images/thumbnails/` | Prefix subroute matches |
| `/images/originals/cat.jpg` | `/images/originals/` | Prefix subroute matches |
| `/images/other.jpg` | 404 | Parent path does not create a fallback location |
| `/static/css/main.css` | `^~/static/css/` | Longest prefix subroute matches |
| `/static/js/app.js` | `^~/static/js/` | Longest prefix subroute matches |
| `/static/fonts/bold.woff` | 404 | Parent path does not create a fallback location |

### Subroute Path Constraints

When a VirtualServer route delegates to a VirtualServerRoute, the following constraints apply to subroute paths:

- **Prefix parent** (`/path`): Multiple subroutes are allowed. Each subroute path must start with the parent path.
  Subroute paths must use the same path type as the parent -- a prefix parent requires prefix subroutes
  (`/images/thumbnails`), not regex (`~/images/thumbnails`) or exact (`=/images/thumbnails`) subroutes.

- **Longest prefix parent** (`^~/path`): Same as prefix -- multiple subroutes are allowed, but each subroute path must
  literally start with the string `^~/path`. This means subroutes must also include the `^~` modifier
  (e.g., `^~/path/sub`). A plain prefix subroute like `/path/sub` is rejected because the string `/path/sub` does not
  start with `^~/path`.

- **Regex parent** (`~/pattern` or `~*/pattern`): Only one subroute is allowed, and it must have the exact same path as
  the parent route.

- **Exact parent** (`=/path`): Only one subroute is allowed, and it must have the exact same path as the parent route.
