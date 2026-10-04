package proxy
import("context";"fmt";"log/slog";"net/http";"net/http/httputil";"net/url";"strings")
type TokenSource interface{AccessToken(context.Context)(string,error)}
type Proxy struct{rp *httputil.ReverseProxy}
func New(raw string,src TokenSource,log *slog.Logger,mappings ...map[string]string)(*Proxy,error){u,e:=url.Parse(raw);if e!=nil||u.Host==""{return nil,fmt.Errorf("invalid upstream URL")};hosts:=map[string]string{};if len(mappings)>0{hosts=mappings[0]};rp:=&httputil.ReverseProxy{Transport:transport{src:src,base:http.DefaultTransport},ErrorHandler:func(w http.ResponseWriter,_ *http.Request,e error){log.Error("proxy request", "error",e);http.Error(w,"upstream request failed",502)}};rp.Rewrite=func(pr *httputil.ProxyRequest){pr.SetURL(u);pr.SetXForwarded();if h,ok:=hosts[strings.ToLower(pr.In.Host)];ok{pr.Out.Host=h}else if h,ok:=hosts["*"];ok{pr.Out.Host=h}};return &Proxy{rp:rp},nil}
func(p *Proxy)ServeHTTP(w http.ResponseWriter,r *http.Request){p.rp.ServeHTTP(w,r)}
type transport struct{src TokenSource;base http.RoundTripper}
func(t transport)RoundTrip(r *http.Request)(*http.Response,error){a,e:=t.src.AccessToken(r.Context());if e!=nil{return nil,fmt.Errorf("get access token: %w",e)};q:=r.Clone(r.Context());q.Header=r.Header.Clone();q.Header.Set("Authorization","Bearer "+a);return t.base.RoundTrip(q)}
