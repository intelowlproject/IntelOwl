variable "REPO_DOWNLOADER_ENABLED" {
  default = "true"
}

variable "CACHE_REPO" {
  default = ""
}

group "default" {
  targets = ["uwsgi", "nginx", "postgres", "redis"]
}

target "uwsgi" {
  context    = "."
  dockerfile = "docker/Dockerfile"
  tags       = ["intelowlproject/intelowl:ci"]
  args = {
    REPO_DOWNLOADER_ENABLED = REPO_DOWNLOADER_ENABLED
  }
  cache-from = CACHE_REPO != "" ? ["type=registry,ref=${CACHE_REPO}:cache-main"] : []
}

target "nginx" {
  context    = "."
  dockerfile = "docker/Dockerfile_nginx"
  tags       = ["intelowlproject/intelowl_nginx:ci"]
  cache-from = CACHE_REPO != "" ? ["type=registry,ref=${CACHE_REPO}:cache-nginx"] : []
}

target "postgres" {
  dockerfile-inline = "FROM postgres:16-alpine"
  tags              = ["postgres:16-alpine"]
}

target "redis" {
  dockerfile-inline = "FROM redis:6.2.7-alpine"
  tags              = ["redis:6.2.7-alpine"]
}
