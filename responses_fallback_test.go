package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/json"
 "io"
 "math/rand"
 "net/http"
 "net/http/httptest"
 "net/url"
 "strings"
 "testing"
 "time"

 "github.com/coder/websocket"
)

// Model a peer rejecting cached WebSocket continuation, followed by the client's
// full HTTP history replay. No private session data or external service is used.
func TestResponsesPeer1009ThenFullHTTPReplay(t *testing.T) {
 t.Setenv("POOL_JWT_SECRET", "fallback-secret")
 block := make([]byte, 48<<10)
 _, _ = rand.New(rand.NewSource(42)).Read(block)
 image := strings.Repeat(base64.StdEncoding.EncodeToString(block), 320) // 20 MiB
 wantHash := sha256.Sum256([]byte(image))
 payload := []byte(`{"model":"gpt-6-astra","stream":true,"input":[{"role":"user","content":[{"type":"input_image","image_url":"` + image + `"}]}]}`)
 upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  if isWebSocketUpgradeRequest(r) {
   conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify:true})
   if err != nil { return }
   defer conn.CloseNow()
   if _, _, err = conn.Read(r.Context()); err == nil {
    _ = conn.Close(websocket.StatusMessageTooBig, "")
   }
   return
  }
  if r.Header.Get("Content-Encoding") != "" { t.Error("encoded body reached upstream") }
  var obj struct { Input []struct { Content []struct { ImageURL string `json:"image_url"` } `json:"content"` } `json:"input"` }
  if err := json.NewDecoder(r.Body).Decode(&obj); err != nil { t.Error(err); http.Error(w,"invalid body",400); return }
  if len(obj.Input)!=1 || len(obj.Input[0].Content)!=1 || sha256.Sum256([]byte(obj.Input[0].Content[0].ImageURL))!=wantHash {
   t.Error("full image history changed or was truncated")
  }
  w.Header().Set("Content-Type","text/event-stream")
  _, _ = io.WriteString(w,preflightResponse)
 }))
 defer upstream.Close()
 base, _ := url.Parse(upstream.URL)
 fx := newCodexProxyFixture(t,base,[]*Account{{Type:AccountTypeCodex,ID:"fallback",AccessToken:"mock-upstream",AccountID:"mock",PlanType:"pro"}})
 fx.handler.cfg.debug.Store(false)
 fx.handler.cfg.maxInMemoryBodyBytes=16<<20
 fx.handler.cfg.maxSpoolBodyBytes=32<<20
 fx.handler.cfg.maxWireBodyBytes=32<<20
 fx.handler.responsesSpoolBodies=make(chan struct{},1)
 completed := make(chan struct{}, 1)
 fx.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  fx.handler.ServeHTTP(w, r)
  if r.Method == http.MethodPost { completed <- struct{}{} }
 })
 auth := "Bearer "+generateClaudePoolToken("fallback-secret","fallback-user")
 conn := dialClientWS(t,fx,http.Header{"Authorization":{auth}})
 defer conn.CloseNow()
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
 defer cancel()
 if err:=conn.Write(ctx,websocket.MessageText,[]byte(`{"type":"response.create","model":"gpt-5.5","input":[]}`));err!=nil { t.Fatal(err) }
 _,_,err:=conn.Read(ctx)
 if websocket.CloseStatus(err)!=websocket.StatusMessageTooBig { t.Fatalf("peer close = %v",err) }
 for _,encoding:=range []string{"","gzip","zstd"} {
  for _,chunked:=range []bool{false,true} {
   name:=encoding
   if name=="" { name="identity" }
   if chunked { name+="/chunked" } else { name+="/known-length" }
   t.Run(name,func(t *testing.T){
    wire:=compressedResponsesBody(t,encoding,payload)
    if encoding!="" && len(wire)>=16<<20 { t.Fatal("fixture must conceal decoded size below RAM threshold") }
    req,_:=http.NewRequest(http.MethodPost,fx.server.URL+"/v1/responses",bytes.NewReader(wire))
    req.Header.Set("Authorization",auth)
    req.Header.Set("Content-Type","application/json")
    req.Header.Set("Content-Encoding",encoding)
    if chunked { req.ContentLength=-1 }
    resp,err:=fx.server.Client().Do(req)
    if err!=nil { t.Fatal(err) }
    defer resp.Body.Close()
    body,_:=io.ReadAll(resp.Body)
    if resp.StatusCode!=200 || string(body)!=preflightResponse { t.Fatalf("HTTP fallback status=%d response=%q",resp.StatusCode,body) }
    select {
    case <-completed:
    case <-time.After(5*time.Second): t.Fatal("HTTP handler did not finish cleanup")
    }
    if len(fx.handler.responsesSpoolBodies)!=0 { t.Error("spool admission leaked") }
   })
  }
 }
}

func TestResponsesDiskThinkingBudgetAndEffortCap(t *testing.T) {
 for _,model:=range []string{"gpt-6-astra(16384)","gpt-6-astra(high)","gpt-6-astra-xhigh-fast"} {
  spool,err:=streamResponsesRequest(strings.NewReader(`{"model":"`+model+`","stream":true,"input":[],"reasoning":{"context":"all_turns"}}`),1<<20,responsesStreamOptions{effortLimit:"low"})
  if err!=nil { t.Fatal(err) }
  body,err:=io.ReadAll(spool.File)
  spool.Close()
  if err!=nil { t.Fatal(err) }
  var obj map[string]any
  if err=json.Unmarshal(body,&obj);err!=nil {t.Fatal(err)}
  reasoning,_:=obj["reasoning"].(map[string]any)
  if obj["model"]!="gpt-6-astra" || reasoning["effort"]!="low" || reasoning["context"]!="all_turns" {t.Fatalf("model/budget/cap/context mismatch: %s",body)}
 }
}
