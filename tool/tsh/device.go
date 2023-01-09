// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"

	"github.com/gravitational/kingpin"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/encoding/protojson"

	devicepb "github.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/devicetrust"
	"github.com/gravitational/teleport/lib/devicetrust/enroll"
	dtnative "github.com/gravitational/teleport/lib/devicetrust/native"
)

type deviceCommand struct {
	enroll *deviceEnrollCommand

	// collect and keyget are debug commands.
	collect *deviceCollectCommand
	keyget  *deviceKeygetCommand
}

func newDeviceCommand(app *kingpin.Application) *deviceCommand {
	root := &deviceCommand{
		enroll:  &deviceEnrollCommand{},
		collect: &deviceCollectCommand{},
		keyget:  &deviceKeygetCommand{},
	}

	// "tsh device" command.
	parentCmd := app.Command(
		"device", "Manage this device. Requires Teleport Enterprise.")

	// "tsh device enroll" command.
	root.enroll.CmdClause = parentCmd.Command(
		"enroll", "Enroll this device as a trusted device. Requires Teleport Enterprise")
	root.enroll.Flag("token", "Device enrollment token").
		Required().
		StringVar(&root.enroll.token)

	// "tsh device" hidden debug commands.
	root.collect.CmdClause = parentCmd.Command("collect", "Simulate enroll/authn device data collection").Hidden()
	root.keyget.CmdClause = parentCmd.Command("keyget", "Get information about the device key").Hidden()

	return root
}

type deviceEnrollCommand struct {
	*kingpin.CmdClause

	token string
}

func (c *deviceEnrollCommand) run(cf *CLIConf) error {
	teleportClient, err := makeClient(cf, true /* useProfileLogin */)
	if err != nil {
		return trace.Wrap(err)
	}

	var dev *devicepb.Device
	ctx := cf.Context
	if err := client.RetryWithRelogin(ctx, teleportClient, func() error {
		proxyClient, err := teleportClient.ConnectToProxy(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		defer proxyClient.Close()

		authClient, err := proxyClient.ConnectToRootCluster(ctx)
		if err != nil {
			return trace.Wrap(err)
		}
		defer authClient.Close()

		devices := authClient.DevicesClient()
		dev, err = enroll.RunCeremony(ctx, devices, c.token)
		return trace.Wrap(err)
	}); err != nil {
		return trace.Wrap(err)
	}

	fmt.Printf(
		"Device %q/%v enrolled\n",
		dev.AssetTag, devicetrust.FriendlyOSType(dev.OsType),
	)
	return nil
}

type deviceCollectCommand struct {
	*kingpin.CmdClause
}

func (c *deviceCollectCommand) run(cf *CLIConf) error {
	cdd, err := dtnative.CollectDeviceData()
	if err != nil {
		return trace.Wrap(err)
	}

	opts := &protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		UseProtoNames: true,
	}
	val, err := opts.Marshal(cdd)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("DeviceCollectedData %s\n", val)
	return nil
}

type deviceKeygetCommand struct {
	*kingpin.CmdClause
}

func (c *deviceKeygetCommand) run(cf *CLIConf) error {
	cred, err := dtnative.GetDeviceCredential()
	if err != nil {
		return trace.Wrap(err)
	}

	opts := &protojson.MarshalOptions{
		Multiline:     true,
		Indent:        "  ",
		UseProtoNames: true,
	}
	val, err := opts.Marshal(cred)
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("DeviceCredential %s\n", val)
	return nil
}
