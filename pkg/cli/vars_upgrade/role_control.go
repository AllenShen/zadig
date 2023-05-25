/*
Copyright 2023 The KodeRover Authors.

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

package vars_upgrade

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/koderover/zadig/pkg/microservice/picket/core/filter/service"
)

type Rule struct {
	Kind      string   `json:"kind"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

type Payload struct {
	Name        string `json:"name"`
	Rules       []Rule `json:"rules"`
	ProjectName string `json:"projectName"`
}

func setUserProjectRole(projectName string, uid, userName, targetRole string) error {
	url := fmt.Sprintf("%s/api/v1/rolebindings/update?projectName=%s&bulk=true&userID=%s", apiUrl, projectName, uid)

	roles := []Role{
		{
			Uid:    uid,
			Role:   targetRole,
			Type:   "custom",
			Preset: isRolePreset(targetRole),
		},
	}
	bs, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bs))

	// 创建http客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// 发起请求
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return errors.New(string(body))
	}

	fmt.Println(fmt.Sprintf("project: %s, user %s:%s role %s => %s ", projectName, userName, uid, fromRole, targetRole))
	return nil
}

func setUserProjectRoleByProject(projectName string) error {
	url := fmt.Sprintf("%s/api/v1/picket/bindings?projectName=%s", apiUrl, projectName)
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var bindings []*service.Binding = make([]*service.Binding, 0)
	err = json.Unmarshal(body, &bindings)
	if err != nil {
		return err
	}

	uids := make(map[string]string)

	for _, binding := range bindings {
		for _, role := range binding.Roles {
			if role.Role == fromRole {
				uids[binding.Uid] = binding.UserName
				break
			}
		}
	}

	for uid, userName := range uids {
		err = setUserProjectRole(projectName, uid, userName, targetRole)
		if err != nil {
			err1 := setUserProjectRole(projectName, uid, userName, fromRole)
			if err1 != nil {
				fmt.Println("failed to set role back for user: ", userName, " uid: ", uid)
			} else {
				fmt.Println("set role back for user: ", userName, " uid: ", uid)
			}
			return err
		}
	}
	return nil
}

type Role struct {
	Uid    string `json:"uid"`
	Role   string `json:"role"`
	Type   string `json:"type"`
	Preset bool   `json:"preset"`
}

func isRolePreset(roleName string) bool {
	if roleName == "project-admin" || roleName == "read-only" || roleName == "read-project-only" {
		return true
	}
	return false
}

func buildPayload(projectName string) ([]byte, error) {
	p := Payload{
		Name: "temp-role",
		Rules: []Rule{
			{
				Kind:      "resource",
				Resources: []string{"Workflow"},
				Verbs:     []string{"get_workflow", "run_workflow", "debug_workflow"},
			},
			{
				Kind:      "resource",
				Resources: []string{"Environment"},
				Verbs:     []string{"get_environment", "debug_pod"},
			},
			{
				Kind:      "resource",
				Resources: []string{"Service"},
				Verbs:     []string{"get_service"},
			},
			{
				Kind:      "resource",
				Resources: []string{"Build"},
				Verbs:     []string{"get_build"},
			},
			{
				Kind:      "resource",
				Resources: []string{"Test"},
				Verbs:     []string{"get_test", "run_test"},
			},
			{
				Kind:      "resource",
				Resources: []string{"Scan"},
				Verbs:     []string{"get_scan", "run_scan"},
			},
		},
		ProjectName: projectName,
	}

	jsonPayload, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err)
		return jsonPayload, err
	}
	return jsonPayload, nil
}

func createTempRoleByProject(projectName string) error {
	url := fmt.Sprintf("%s/api/v1/roles?projectName=%s", apiUrl, projectName)

	jsonPayload, err := buildPayload(projectName)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))

	// 创建http客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// 发起请求
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// 处理响应
		body, _ := ioutil.ReadAll(resp.Body)
		if strings.Contains(string(body), "E11000 duplicate key error collection: ") {
			return nil
		}
		return errors.New(string(body))
	}

	return nil
}

func fetchSingleProjectBindings(projectName string) error {
	url := fmt.Sprintf("%s/api/v1/picket/bindings?projectName=%s", apiUrl, projectName)
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		fmt.Println(err)
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var bindings []*service.Binding = make([]*service.Binding, 0)
	err = json.Unmarshal(body, &bindings)
	if err != nil {
		return err
	}

	for _, binding := range bindings {
		for _, role := range binding.Roles {
			if role.Role == "project-admin" {
				fmt.Printf("++++++++++++ user with role project-admin in project: %s, [%s/%s/%s]\n", projectName, binding.UserName, binding.Account, binding.Uid)
				break
			}
		}
	}

	return nil
}

func fetchAllProjectAdmins() error {
	fmt.Println(fmt.Sprintf("******** start fetching project admin users for %d projects ********", len(k8sProjects)))
	for _, project := range k8sProjects {
		err := fetchSingleProjectBindings(project.ProductName)
		if err != nil {
			return errors.Wrapf(err, "failed to query userbings for project: %s", project.ProductName)
		}
	}
	return nil
}

func createTempRoles() error {
	fmt.Println(fmt.Sprintf("******** start creating temp roles for %d projects ********", len(k8sProjects)))
	for _, project := range k8sProjects {
		err := createTempRoleByProject(project.ProductName)
		if err != nil {
			fmt.Printf(fmt.Sprintf("failed to query create temp role for project: %s, err: %s \n", project.ProductName, err.Error()))
		} else {
			fmt.Printf(fmt.Sprintf("temp role for project: %s  created successfully \n", project.ProductName))
		}
	}
	return nil
}

func setUserProjectRoles() error {
	fmt.Println(fmt.Sprintf("******** start setting user role for %d projects ********", len(k8sProjects)))
	for _, project := range k8sProjects {
		err := setUserProjectRoleByProject(project.ProductName)
		if err != nil {
			return errors.Wrapf(err, "failed to set user role for project: %s", project.ProductName)
		}
	}
	return nil
}
