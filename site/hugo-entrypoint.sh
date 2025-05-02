#!/bin/sh

hugo mod get -u github.com/nginxinc/nginx-hugo-theme
hugo --environment docker $*
