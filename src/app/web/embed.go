package web

import "embed"

//go:embed index.html login.html app.js style.css favicon.svg
var FS embed.FS
