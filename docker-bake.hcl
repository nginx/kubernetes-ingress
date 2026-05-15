variable "IC_VERSION" {
  default = "dev"
}

variable "NGINX_OSS_VERSION" {
  # renovate: datasource=docker depName=nginx/nginx
  default = "1.29.8"
}

variable "NGINX_PLUS_VERSION" {
  # renovate: datasource=nginx-plus depName=nginx-plus
  default = "R36"
}

variable "NAP_WAF_VERSION" {
  default = "36+5.607"
}

variable "NAP_WAF_COMMON_VERSION" {
  default = "11.644"
}

variable "NAP_WAF_PLUGIN_VERSION" {
  default = "6.28"
}

variable "NGINX_AGENT_VERSION" {
  default = "3.9"
}

variable "NAP_AGENT_VERSION" {
  default = "2"
}

variable "PACKAGE_REPO" {
  default = "pkgs.nginx.com"
}

variable "DOWNLOAD_TAG" {
  default = "edge"
}

variable "PREBUILT_BASE_IMG" {
  default = "nginx/nginx-ingress:edge"
}

variable "IMAGE_NAME" {
  default = "nginx/nginx-ingress"
}

target "_shared-common" {
  context    = "."
  dockerfile = "build/Dockerfile.shared"
}

target "_golang-builder" {
  inherits = ["_shared-common"]
  target   = "golang-builder"
}

target "_ubi-minimal" {
  inherits = ["_shared-common"]
  target   = "ubi-minimal"
}

target "_ubi8-packages" {
  inherits = ["_shared-common"]
  target   = "ubi8-packages"
}

target "_ubi9-packages" {
  inherits = ["_shared-common"]
  target   = "ubi9-packages"
}

target "_alpine-fips" {
  inherits = ["_shared-common"]
  target   = "alpine-fips-3.22"
}

target "_nginx-files-common" {
  inherits = ["_shared-common"]
  target   = "nginx-files"
  args = {
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-debian" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "debian"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-alpine" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "alpine"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-ubi" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "ubi"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-alpine-plus" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "alpine-plus"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-alpine-plus-fips" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "alpine-plus-fips"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-alpine-plus-nap-fips" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "alpine-plus-nap-fips"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-alpine-plus-nap-v5-fips" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "alpine-plus-nap-v5-fips"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-debian-plus" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "debian-plus"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-debian-plus-nap" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "debian-plus-nap"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-debian-plus-nap-v5" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "debian-plus-nap-v5"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-ubi-9-plus" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "ubi-9-plus"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-ubi-9-plus-nap" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "ubi-9-plus-nap"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-ubi-9-plus-nap-v5" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "ubi-9-plus-nap-v5"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-ubi-8-plus-nap" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "ubi-8-plus-nap"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_nginx-files-ubi-8-plus-nap-v5" {
  inherits = ["_nginx-files-common"]
  args = {
    BUILD_OS           = "ubi-8-plus-nap-v5"
    IC_VERSION         = IC_VERSION
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    PACKAGE_REPO       = PACKAGE_REPO
  }
}

target "_oss-common" {
  context    = "."
  dockerfile = "build/Dockerfile.oss"
  args = {
    IC_VERSION          = IC_VERSION
    NGINX_OSS_VERSION   = NGINX_OSS_VERSION
    NGINX_AGENT_VERSION = NGINX_AGENT_VERSION
    PACKAGE_REPO        = PACKAGE_REPO
  }
}

target "_oss-debian" {
  inherits = ["_oss-common"]
  target   = "debian"
  contexts = {
    "nginx-files" = "target:_nginx-files-debian"
  }
}

target "_oss-alpine" {
  inherits = ["_oss-common"]
  target   = "alpine"
  contexts = {
    "nginx-files" = "target:_nginx-files-alpine"
  }
}

target "_oss-ubi" {
  inherits = ["_oss-common"]
  target   = "ubi"
  contexts = {
    "nginx-files"  = "target:_nginx-files-ubi"
    "ubi-minimal"  = "target:_ubi-minimal"
    "ubi9-packages" = "target:_ubi9-packages"
  }
}

target "_debian-plus-common" {
  context    = "."
  dockerfile = "build/Dockerfile.debian-plus"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
  ]
  args = {
    NGINX_PLUS_VERSION     = NGINX_PLUS_VERSION
    NGINX_AGENT_VERSION    = NGINX_AGENT_VERSION
    NAP_WAF_VERSION        = NAP_WAF_VERSION
    NAP_WAF_COMMON_VERSION = NAP_WAF_COMMON_VERSION
    NAP_WAF_PLUGIN_VERSION = NAP_WAF_PLUGIN_VERSION
    NAP_AGENT_VERSION      = NAP_AGENT_VERSION
  }
}

target "_debian-plus" {
  inherits = ["_debian-plus-common"]
  target   = "debian-plus"
  contexts = {
    "nginx-files" = "target:_nginx-files-debian-plus"
  }
}

target "_debian-plus-nap-waf" {
  inherits = ["_debian-plus-common"]
  target   = "debian-plus-nap"
  contexts = {
    "nginx-files" = "target:_nginx-files-debian-plus-nap"
  }
  args = {
    NAP_MODULES            = "waf"
    NGINX_PLUS_VERSION     = NGINX_PLUS_VERSION
    NAP_WAF_VERSION        = NAP_WAF_VERSION
    NAP_WAF_COMMON_VERSION = NAP_WAF_COMMON_VERSION
    NAP_WAF_PLUGIN_VERSION = NAP_WAF_PLUGIN_VERSION
    NAP_AGENT_VERSION      = NAP_AGENT_VERSION
  }
}

target "_debian-plus-nap-dos" {
  inherits = ["_debian-plus-common"]
  target   = "debian-plus-nap"
  contexts = {
    "nginx-files" = "target:_nginx-files-debian-plus-nap"
  }
  args = {
    NAP_MODULES        = "dos"
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
  }
}

target "_debian-plus-nap-waf-dos" {
  inherits = ["_debian-plus-common"]
  target   = "debian-plus-nap"
  contexts = {
    "nginx-files" = "target:_nginx-files-debian-plus-nap"
  }
  args = {
    NAP_MODULES            = "waf,dos"
    NGINX_PLUS_VERSION     = NGINX_PLUS_VERSION
    NAP_WAF_VERSION        = NAP_WAF_VERSION
    NAP_WAF_COMMON_VERSION = NAP_WAF_COMMON_VERSION
    NAP_WAF_PLUGIN_VERSION = NAP_WAF_PLUGIN_VERSION
    NAP_AGENT_VERSION      = NAP_AGENT_VERSION
  }
}

target "_debian-plus-nap-v5" {
  inherits = ["_debian-plus-common"]
  target   = "debian-plus-nap-v5"
  contexts = {
    "nginx-files" = "target:_nginx-files-debian-plus-nap-v5"
  }
}

target "_alpine-plus-common" {
  context    = "."
  dockerfile = "build/Dockerfile.alpine-plus"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
  ]
  args = {
    NGINX_PLUS_VERSION  = NGINX_PLUS_VERSION
    NGINX_AGENT_VERSION = NGINX_AGENT_VERSION
    NAP_WAF_VERSION     = NAP_WAF_VERSION
    NAP_AGENT_VERSION   = NAP_AGENT_VERSION
    PACKAGE_REPO        = PACKAGE_REPO
  }
}

target "_alpine-plus" {
  inherits = ["_alpine-plus-common"]
  target   = "alpine-plus"
  contexts = {
    "nginx-files" = "target:_nginx-files-alpine-plus"
  }
}

target "_alpine-plus-fips" {
  inherits = ["_alpine-plus-common"]
  target   = "alpine-plus-fips"
  contexts = {
    "nginx-files"      = "target:_nginx-files-alpine-plus-fips"
    "alpine-fips-3.22" = "target:_alpine-fips"
  }
}

target "_alpine-plus-nap-fips" {
  inherits = ["_alpine-plus-common"]
  target   = "alpine-plus-nap-fips"
  contexts = {
    "nginx-files"      = "target:_nginx-files-alpine-plus-nap-fips"
    "alpine-fips-3.22" = "target:_alpine-fips"
  }
}

target "_alpine-plus-nap-v5-fips" {
  inherits = ["_alpine-plus-common"]
  target   = "alpine-plus-nap-v5-fips"
  contexts = {
    "nginx-files"      = "target:_nginx-files-alpine-plus-nap-v5-fips"
    "alpine-fips-3.22" = "target:_alpine-fips"
  }
}

target "_ubi-plus-common" {
  context    = "."
  dockerfile = "build/Dockerfile.ubi-plus"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
  ]
  args = {
    NGINX_PLUS_VERSION  = NGINX_PLUS_VERSION
    NGINX_AGENT_VERSION = NGINX_AGENT_VERSION
    NAP_WAF_VERSION     = NAP_WAF_VERSION
    NAP_AGENT_VERSION   = NAP_AGENT_VERSION
  }
}

target "_ubi-9-plus" {
  inherits = ["_ubi-plus-common"]
  target   = "ubi-9-plus"
  contexts = {
    "nginx-files"  = "target:_nginx-files-ubi-9-plus"
    "ubi-minimal"  = "target:_ubi-minimal"
    "ubi9-packages" = "target:_ubi9-packages"
  }
}

target "_ubi-9-plus-nap-waf" {
  inherits = ["_ubi-plus-common"]
  target   = "ubi-9-plus-nap"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
    "id=rhel_license,src=rhel_license",
  ]
  contexts = {
    "nginx-files"  = "target:_nginx-files-ubi-9-plus-nap"
    "ubi-minimal"  = "target:_ubi-minimal"
    "ubi9-packages" = "target:_ubi9-packages"
  }
  args = {
    BUILD_OS           = "ubi-9-plus-nap"
    NAP_MODULES        = "waf"
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    NAP_WAF_VERSION    = NAP_WAF_VERSION
    NAP_AGENT_VERSION  = NAP_AGENT_VERSION
  }
}

target "_ubi-9-plus-nap-dos" {
  inherits = ["_ubi-9-plus-nap-waf"]
  args = {
    BUILD_OS           = "ubi-9-plus-nap"
    NAP_MODULES        = "dos"
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
  }
}

target "_ubi-9-plus-nap-waf-dos" {
  inherits = ["_ubi-9-plus-nap-waf"]
  args = {
    BUILD_OS           = "ubi-9-plus-nap"
    NAP_MODULES        = "waf,dos"
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    NAP_WAF_VERSION    = NAP_WAF_VERSION
    NAP_AGENT_VERSION  = NAP_AGENT_VERSION
  }
}

target "_ubi-9-plus-nap-v5" {
  inherits = ["_ubi-plus-common"]
  target   = "ubi-9-plus-nap-v5"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
    "id=rhel_license,src=rhel_license",
  ]
  contexts = {
    "nginx-files"  = "target:_nginx-files-ubi-9-plus-nap-v5"
    "ubi-minimal"  = "target:_ubi-minimal"
    "ubi9-packages" = "target:_ubi9-packages"
  }
}

target "_ubi-8-plus-nap" {
  inherits = ["_ubi-plus-common"]
  target   = "ubi-8-plus-nap"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
    "id=rhel_license,src=rhel_license",
  ]
  contexts = {
    "nginx-files"   = "target:_nginx-files-ubi-8-plus-nap"
    "ubi8-packages" = "target:_ubi8-packages"
  }
  args = {
    BUILD_OS           = "ubi-8-plus-nap"
    NGINX_PLUS_VERSION = NGINX_PLUS_VERSION
    NAP_WAF_VERSION    = NAP_WAF_VERSION
    NAP_AGENT_VERSION  = NAP_AGENT_VERSION
  }
}

target "_ubi-8-plus-nap-v5" {
  inherits = ["_ubi-plus-common"]
  target   = "ubi-8-plus-nap-v5"
  secret = [
    "id=nginx-repo.crt,src=nginx-repo.crt",
    "id=nginx-repo.key,src=nginx-repo.key",
    "id=rhel_license,src=rhel_license",
  ]
  contexts = {
    "nginx-files"   = "target:_nginx-files-ubi-8-plus-nap-v5"
    "ubi8-packages" = "target:_ubi8-packages"
  }
}

target "_final-common" {
  context    = "."
  dockerfile = "build/Dockerfile.targets"
  target     = "local"
  contexts = {
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    IC_VERSION        = IC_VERSION
    PREBUILT_BASE_IMG = PREBUILT_BASE_IMG
    DOWNLOAD_TAG      = DOWNLOAD_TAG
    IMAGE_NAME        = IMAGE_NAME
  }
}

target "debian-image" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_oss-debian"
    "nginx-files"    = "target:_nginx-files-debian"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "debian"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_OSS_VERSION
  }
}

target "alpine-image" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_oss-alpine"
    "nginx-files"    = "target:_nginx-files-alpine"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "alpine"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_OSS_VERSION
  }
}

target "ubi-image" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_oss-ubi"
    "nginx-files"    = "target:_nginx-files-ubi"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_OSS_VERSION
  }
}

target "debian-image-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_debian-plus"
    "nginx-files"    = "target:_nginx-files-debian-plus"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "debian-plus"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "debian-image-nap-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_debian-plus-nap-waf"
    "nginx-files"    = "target:_nginx-files-debian-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "debian-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "waf"
  }
}

target "debian-image-nap-v5-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_debian-plus-nap-v5"
    "nginx-files"    = "target:_nginx-files-debian-plus-nap-v5"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "debian-plus-nap-v5"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "debian-image-dos-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_debian-plus-nap-dos"
    "nginx-files"    = "target:_nginx-files-debian-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "debian-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "dos"
    NAP_MODULES_AWS = "dos"
  }
}

target "debian-image-nap-dos-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_debian-plus-nap-waf-dos"
    "nginx-files"    = "target:_nginx-files-debian-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "debian-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "waf,dos"
    NAP_MODULES_AWS = "both"
  }
}

target "alpine-image-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_alpine-plus"
    "nginx-files"    = "target:_nginx-files-alpine-plus"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "alpine-plus"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "alpine-image-plus-fips" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_alpine-plus-fips"
    "nginx-files"    = "target:_nginx-files-alpine-plus-fips"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "alpine-plus-fips"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "alpine-image-nap-plus-fips" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_alpine-plus-nap-fips"
    "nginx-files"    = "target:_nginx-files-alpine-plus-nap-fips"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "alpine-plus-nap-fips"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "waf"
  }
}

target "alpine-image-nap-v5-plus-fips" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_alpine-plus-nap-v5-fips"
    "nginx-files"    = "target:_nginx-files-alpine-plus-nap-v5-fips"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "alpine-plus-nap-v5-fips"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "ubi-image-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-9-plus"
    "nginx-files"    = "target:_nginx-files-ubi-9-plus"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-9-plus"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "ubi-image-nap-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-9-plus-nap-waf"
    "nginx-files"    = "target:_nginx-files-ubi-9-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-9-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "waf"
  }
}

target "ubi-image-nap-v5-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-9-plus-nap-v5"
    "nginx-files"    = "target:_nginx-files-ubi-9-plus-nap-v5"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-9-plus-nap-v5"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "ubi-image-dos-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-9-plus-nap-dos"
    "nginx-files"    = "target:_nginx-files-ubi-9-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-9-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "dos"
    NAP_MODULES_AWS = "dos"
  }
}

target "ubi-image-nap-dos-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-9-plus-nap-waf-dos"
    "nginx-files"    = "target:_nginx-files-ubi-9-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-9-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "waf,dos"
    NAP_MODULES_AWS = "both"
  }
}

target "ubi8-image-nap-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-8-plus-nap"
    "nginx-files"    = "target:_nginx-files-ubi-8-plus-nap"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-8-plus-nap"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
    NAP_MODULES   = "waf"
  }
}

target "ubi8-image-nap-v5-plus" {
  inherits = ["_final-common"]
  contexts = {
    "build-os"       = "target:_ubi-8-plus-nap-v5"
    "nginx-files"    = "target:_nginx-files-ubi-8-plus-nap-v5"
    "golang-builder" = "target:_golang-builder"
  }
  args = {
    BUILD_OS      = "ubi-8-plus-nap-v5"
    IC_VERSION    = IC_VERSION
    NGINX_VERSION = NGINX_PLUS_VERSION
  }
}

target "patch-os-image" {
  inherits = ["_final-common"]
  target   = "patched"
  contexts = {
    "nginx-files"    = "target:_nginx-files-debian"
    "golang-builder" = "target:_golang-builder"
  }
}

group "oss" {
  targets = ["debian-image", "alpine-image", "ubi-image"]
}

group "plus" {
  targets = ["debian-image-plus", "alpine-image-plus", "alpine-image-plus-fips", "ubi-image-plus"]
}

group "nap" {
  targets = [
    "debian-image-nap-plus",
    "debian-image-nap-v5-plus",
    "debian-image-dos-plus",
    "debian-image-nap-dos-plus",
    "alpine-image-nap-plus-fips",
    "alpine-image-nap-v5-plus-fips",
    "ubi-image-nap-plus",
    "ubi8-image-nap-plus",
    "ubi-image-nap-v5-plus",
    "ubi8-image-nap-v5-plus",
    "ubi-image-dos-plus",
    "ubi-image-nap-dos-plus",
  ]
}

group "all" {
  targets = [
    "debian-image",
    "alpine-image",
    "ubi-image",
    "debian-image-plus",
    "alpine-image-plus",
    "alpine-image-plus-fips",
    "ubi-image-plus",
    "debian-image-nap-plus",
    "debian-image-nap-v5-plus",
    "debian-image-dos-plus",
    "debian-image-nap-dos-plus",
    "alpine-image-nap-plus-fips",
    "alpine-image-nap-v5-plus-fips",
    "ubi-image-nap-plus",
    "ubi8-image-nap-plus",
    "ubi-image-nap-v5-plus",
    "ubi8-image-nap-v5-plus",
    "ubi-image-dos-plus",
    "ubi-image-nap-dos-plus",
  ]
}
