package httputils

import (
	"github.com/alessiosavi/GoUtils"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"path"
	"strconv"
)

func ListAndServerGZIP(host string, _port int, gzipHandler fasthttp.RequestHandler) {
	port := strconv.Itoa(_port)
	log.Info("ListAndServerGZIP | Trying estabilishing connection @[http://", host, ":", port)
	err := fasthttp.ListenAndServe(host+":"+port, gzipHandler) // Try to start the server with input "host:port" received in input
	if err != nil {                                            // No luck, connection not succesfully. Probably port used ...
		log.Warn("ListAndServerGZIP | Port [", port, "] seems used :/")
		for i := 0; i < 10; i++ {
			port := strconv.Itoa(utils.Random(8081, 8090)) // Generate a new port to use
			log.Info("ListAndServerGZIP | Round ", strconv.Itoa(i), "] No luck! Connecting to anotother random port [@", port, "] ...")
			err := fasthttp.ListenAndServe(host+":"+port, gzipHandler) // Trying with the random port generate few step above
			if err == nil {                                            // Connection estabileshed! Not reached
				log.Info("ListAndServerGZIP | Connection estabilished @[http://", host, ":", port)
				break
			}
		}
	}
}

func ListAndServerSSL(host, _path, pub, priv string, _port int, gzipHandler fasthttp.RequestHandler) {

	if utils.VerifyCert(_path, pub, priv) {
		port := strconv.Itoa(_port)
		log.Info("ListAndServerSSL | Trying estabilishing connection @[https://", host, ":", port)
		err := fasthttp.ListenAndServeTLS(host+":"+port, path.Join(_path, pub), path.Join(_path, priv), gzipHandler) // Try to start the server with input "host:port" received in input
		if err != nil {                                                                                              // No luck, connection not succesfully. Probably port used ...
			log.Warn("ListAndServerSSL | Port [", port, "] seems used :/")
			for i := 0; i < 10; i++ {
				port := strconv.Itoa(utils.Random(8081, 8090)) // Generate a new port to use
				log.Info("ListAndServerSSL | Round ", strconv.Itoa(i), "] No luck! Connecting to anotother random port [@", port, "] ...")
				err := fasthttp.ListenAndServeTLS(host+":"+port, path.Join(_path, pub), path.Join(_path, priv), gzipHandler) // Trying with the random port generate few step above
				if err == nil {                                                                                              // Connection estabileshed! Not reached
					log.Info("ListAndServerSSL | Connection estabilished @[https://", host, ":", port)
					break
				}
			}
		}
	}
}

func SecureRequest(ctx *fasthttp.RequestCtx, ssl bool) {
	ctx.Response.Header.Set("X-Frame-Options", "DENY")
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Response.Header.Set("X-XSS-Protection", "1; mode=block")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	if ssl {
		ctx.Response.Header.Set("Content-Security-Policy", "upgrade-insecure-requests")
		ctx.Response.Header.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}

}