package proxy
import("context";"fmt";"log/slog";"net/http";"net/http/httputil";"net/url")
type TokenSource interface{AccessToken(context.Context)(string,error)}
type Proxy struct{rp *httputil.ReverseProxy}
func New(raw string,src TokenSource,log *slog.Logger)(*Proxy,error){u,e:=url.Parse(raw);if e!=nil||u.Scheme!="https"||u.Host==""{return nil,fmt.Errorf("invalid upstream URL")};rp:=&httputil.ReverseProxy{Transport:transport{src:src,base:http.DefaultTransport},ErrorHandler:func(w http.ResponseWriter,_ *http.Request,e error){log.Error("proxy request", "error",e);http.Error(w,"upstream request failed",502)}};rp.Rewrite=func(pr *httputil.ProxyRequest){pr.SetURL(u);pr.SetXForwarded()};return &Proxy{rp:rp},nil}
func(p *Proxy)ServeHTTP(w http.ResponseWriter,r *http.Request){p.rp.ServeHTTP(w,r)}
type transport struct{src TokenSource;base http.RoundTripper}
func(t transport)RoundTrip(r *http.Request)(*http.Response,error){a,e:=t.src.AccessToken(r.Context());if e!=nil{return nil,fmt.Errorf("get access token: %w",e)};q:=r.Clone(r.Context());q.Header=r.Header.Clone();q.Header.Set("Authorization","Bearer "+a);return t.base.RoundTrip(q)}
