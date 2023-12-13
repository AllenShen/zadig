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

package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/koderover/zadig/v2/pkg/microservice/picket/core/evaluation/service"
	internalhandler "github.com/koderover/zadig/v2/pkg/shared/handler"
	e "github.com/koderover/zadig/v2/pkg/tool/errors"
)

type evaluateArgs struct {
	Data []service.GrantReq `json:"data"`
}

type evaluateResp struct {
	Data interface{} `json:"data"`
}

func Evaluate(c *gin.Context) {
	ctx := internalhandler.NewContext(c)
	defer func() { internalhandler.JSONResponse(c, ctx) }()
	projectName := c.Query("projectName")
	if projectName == "" {
		ctx.Err = e.ErrInvalidParam.AddDesc("invalid EvaluateArgs , projectName is empty")
		return
	}
	args := new(evaluateArgs)

	if err := c.ShouldBindJSON(args); err != nil {
		ctx.Err = e.ErrInvalidParam.AddErr(err).AddDesc("invalid EvaluateArgs")
		return
	}
	data, err := service.Evaluate(c.Request.Header, projectName, args.Data, ctx.Logger)
	ctx.Resp = evaluateResp{Data: data}
	ctx.Err = err
}
