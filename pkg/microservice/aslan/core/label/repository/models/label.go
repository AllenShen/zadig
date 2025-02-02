/*
Copyright 2022 The KodeRover Authors.

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

package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/koderover/zadig/pkg/setting"
)

type Label struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"               json:"id,omitempty"`
	Type        setting.LabelType  `bson:"type"                        json:"type"`
	Key         string             `bson:"key"                         json:"key"`
	Value       string             `bson:"value"                       json:"value"`
	CreateBy    string             `bson:"create_by"                   json:"create_by"`
	CreateTime  int64              `bson:"create_time"                 json:"create_time"`
	ProjectName string             `bson:"project_name"                json:"project_name"`
}

func (Label) TableName() string {
	return "label"
}
