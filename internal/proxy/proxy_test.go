package proxy

import("context";"log/slog";"net/http";"net/http/httptest";"testing")
type testToken string
func(t testToken)AccessToken(context.Context)(string,error){return string(t),nil}
func TestProxyReplacesAuthorizationAndForwardsPath(t *testing.T){got:=make(chan *http.Request,1);u:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){got<-r.Clone(r.Context());w.WriteHeader(204)}));defer u.Close();p,e:=New(u.URL,testToken("new"),slog.Default(),map[string]string{"service.local":"api.internal"});if e!=nil{t.Fatal(e)};r:=httptest.NewRequest(http.MethodGet,"http://local/v1/foo?q=1",nil);r.Host="service.local";r.Header.Set("Authorization","Bearer old");w:=httptest.NewRecorder();p.ServeHTTP(w,r);if w.Code!=204{t.Fatalf("status %d",w.Code)};x:=<-got;if x.URL.Path!="/v1/foo"||x.URL.RawQuery!="q=1"||x.Header.Get("Authorization")!="Bearer new"||x.Host!="api.internal"{t.Fatalf("bad upstream request: %s %s %q host=%q",x.URL.Path,x.URL.RawQuery,x.Header.Get("Authorization"),x.Host)}}
