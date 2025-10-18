package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// startHTTP starts a lightweight HTTP server that exposes the TCP state table
// both as JSON (/dump) and as a simple auto-refreshing HTML page (/).
func startHTTP() {
	http.HandleFunc("/dump", func(w http.ResponseWriter, r *http.Request) {
		snap := tcpTable.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		snap.FormatTimes()
		_ = enc.Encode(snap)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>TCP State Table</title>
  <style>
    body{font-family:sans-serif;margin:20px;}
    table{border-collapse:collapse;width:100%;}
    th,td{border:1px solid #ddd;padding:6px;font-size:14px;}
    th{background:#f3f3f3;position:sticky;top:0;}
    code{background:#f7f7f7;padding:1px 3px;border-radius:3px;}
  </style>
</head>
<body>
  <h1>TCP State Table</h1>
  <p>Auto-refreshes every 2s. JSON: <a href="/dump">/dump</a></p>
  <div id="stats"></div>
  <table id="tbl">
    <thead><tr><th>Src</th><th>Dst</th><th>State</th><th>Origin?</th><th>LastSeen</th></tr></thead>
    <tbody></tbody>
  </table>
<script>
async function refresh(){
  const r = await fetch('/dump'); const s = await r.json();
  document.getElementById('stats').innerHTML =
    '<b>Now:</b> '+s.now+' &nbsp; <b>Total:</b> '+s.total+
    ' &nbsp; <b>Half-open:</b> '+s.half_open+
    ' &nbsp; <b>Counts:</b> <code>'+JSON.stringify(s.counts)+'</code>'+
    '<br><b>SYN/s by src (window):</b> <code>'+JSON.stringify(s.syn_by_src_per_window)+'</code>'+
    '<br><b>RST/s by src (window):</b> <code>'+JSON.stringify(s.rst_by_src_per_window)+'</code>'+
    '<br><b>Banned until:</b> <code>'+JSON.stringify(s.banned_until)+'</code>';
  const tb = document.querySelector('#tbl tbody'); tb.innerHTML = '';
  s.entries.sort((a,b)=> (a.state>b.state?1:-1));
  for(const e of s.entries){
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>'+e.key.src_ip+':'+e.key.src_port+'</td>'+
      '<td>'+e.key.dst_ip+':'+e.key.dst_port+'</td>'+
      '<td>'+e.state+'</td>'+
      '<td>'+(e.is_origin?'yes':'no')+'</td>'+
      '<td>'+e.last_seen+'</td>';
    tb.appendChild(tr);
  }
}
setInterval(refresh, 2000); refresh();
</script>
</body></html>`)
	})

	go func() {
		addr := ":8080"
		log.Printf("http: serving state table on %s (/, /dump)", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("http server error: %v", err)
		}
	}()
}
