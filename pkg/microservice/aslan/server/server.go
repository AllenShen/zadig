/*
Copyright 2021 The KodeRover Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"context"
	"net/http"
	"net/http/pprof"
	_ "net/http/pprof"
	"time"

	"github.com/gorilla/mux"
	"github.com/koderover/zadig/v2/pkg/microservice/aslan/core"
	"github.com/koderover/zadig/v2/pkg/microservice/aslan/server/rest"
	"github.com/koderover/zadig/v2/pkg/tool/kube/client"
	"github.com/koderover/zadig/v2/pkg/tool/log"
)

func Serve(ctx context.Context) error {
	go func() {
		if err := client.Start(ctx); err != nil {
			panic(err)
		}
	}()

	core.Start(ctx)
	defer core.Stop(ctx)

	log.Infof("App Aslan Started at %s", time.Now())

	engine := rest.NewEngine()
	server := &http.Server{
		Addr:         ":25000",
		WriteTimeout: time.Second * 3600,
		ReadTimeout:  time.Second * 3600,
		IdleTimeout:  time.Second * 5 * 60,
		Handler:      engine,
	}

	stopChan := make(chan struct{})
	go func() {
		defer close(stopChan)

		<-ctx.Done()

		ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Errorf("Failed to stop server, error: %s", err)
		}
	}()

	// pprof service, you can access it by {your_ip}:8888/debug/pprof
	go func() {
		router := mux.NewRouter()
		router.Handle("/debug/pprof", http.HandlerFunc(pprof.Index))
		router.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		router.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		router.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		router.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
		router.Handle("/debug/pprof/{cmd}", http.HandlerFunc(pprof.Index))
		err := http.ListenAndServe("0.0.0.0:8888", router)
		if err != nil {
			log.Fatal(err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("Failed to start http server, error: %s", err)
		return err
	}

	<-stopChan

	return nil
}
