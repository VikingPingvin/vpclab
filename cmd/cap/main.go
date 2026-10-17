// Command cap runs exercises: it creates a broken AWS setup in Floci, lets
// the learner fix it with the AWS CLI or Terraform, and checks the result
// with real traffic through vpcsim.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/VikingPingvin/vpclab/internal/exercise"
	"github.com/VikingPingvin/vpclab/internal/floci"
	"github.com/VikingPingvin/vpclab/internal/naming"
)

const usage = `usage: cap <command>

commands:
  list           show the available exercises
  start <name>   create the exercise in Floci and show the task
  status         show the task, the resources and their IDs and addresses
  verify         check your solution with real traffic
  hint           show the next hint
  reset          remove the exercise and start it again from the beginning
  stop           remove the exercise's resources

vpcsim must run: start the lab with scripts/vpclab.sh up

environment:
  CAP_EXERCISES   exercise directory (default exercises)
  CAP_STATE       state file (default .cap/state.json)
`

// settle is how long verify waits for vpcsim to apply the latest changes:
// one reconcile interval (2 s) plus the time a reconcile takes.
const settle = 3 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := &app{dir: env("CAP_EXERCISES", "exercises"), statePath: env("CAP_STATE", ".cap/state.json")}
	var err error
	switch cmd := os.Args[1]; {
	case cmd == "list":
		err = app.list()
	case cmd == "start" && len(os.Args) == 3:
		err = app.start(ctx, os.Args[2])
	case cmd == "status":
		err = app.status(ctx)
	case cmd == "verify":
		err = app.verify(ctx)
	case cmd == "hint":
		err = app.hint()
	case cmd == "reset":
		err = app.reset(ctx)
	case cmd == "stop":
		err = app.stop(ctx)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cap:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type app struct {
	dir       string
	statePath string
}

var errFailed = errors.New("some checks fail")

// current loads the running exercise and its definition.
func (a *app) current() (*exercise.Exercise, *exercise.State, error) {
	st, err := exercise.LoadState(a.statePath)
	if err != nil {
		return nil, nil, err
	}
	if st == nil {
		return nil, nil, errors.New("no exercise is running; see cap list and cap start <name>")
	}
	ex, err := exercise.Load(a.dir, st.Exercise)
	return ex, st, err
}

func (a *app) list() error {
	all, err := exercise.LoadAll(a.dir)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, ex := range all {
		fmt.Fprintf(w, "%s\t%s\n", ex.Name, ex.Summary)
	}
	return w.Flush()
}

func (a *app) start(ctx context.Context, name string) error {
	if st, err := exercise.LoadState(a.statePath); err != nil {
		return err
	} else if st != nil {
		return fmt.Errorf("exercise %s is running; run cap stop first", st.Exercise)
	}
	ex, err := exercise.Load(a.dir, name)
	if err != nil {
		return err
	}
	c, err := floci.EC2(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Creating %s in Floci...\n", ex.Name)
	st, err := exercise.Start(ctx, c, ex)
	if err != nil {
		return err
	}
	if err := exercise.SaveState(a.statePath, st); err != nil {
		return err
	}
	if err := waitForInstances(ctx, ex, st); err != nil {
		return err
	}
	return a.printStatus(ctx, c, ex, st)
}

// waitForInstances waits until vpcsim runs a container for every instance.
// The first start can include an image pull.
func waitForInstances(ctx context.Context, ex *exercise.Exercise, st *exercise.State) error {
	if !reconcilerRunning(ctx) {
		return errors.New("the exercise exists in Floci, but vpcsim is not running; start the lab with scripts/vpclab.sh up, then run cap status")
	}
	fmt.Println("Waiting for vpcsim to start the instances...")
	deadline := time.Now().Add(2 * time.Minute)
	for _, in := range ex.Resources.Instances {
		name := naming.InstanceContainer(st.IDs[in.Name])
		for {
			out, _ := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", name).Output()
			if strings.TrimSpace(string(out)) == "true" {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("no running container %s after 2 minutes; check the vpcsim terminal for errors", name)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
	}
	return nil
}

// reconcilerRunning reports whether a reconciler runs: the background one of
// vpclab up, or a foreground scripts/vpcsim.sh run.
func reconcilerRunning(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "docker", "ps", "--no-trunc", "--format", "{{.Command}}").Output()
	return err == nil && strings.Contains(string(out), "vpcsim run")
}

func (a *app) status(ctx context.Context) error {
	ex, st, err := a.current()
	if err != nil {
		return err
	}
	c, err := floci.EC2(ctx)
	if err != nil {
		return err
	}
	return a.printStatus(ctx, c, ex, st)
}

func (a *app) printStatus(ctx context.Context, c *ec2.Client, ex *exercise.Exercise, st *exercise.State) error {
	fmt.Printf("\n%s (%s)\n\n%s\n", ex.Title, ex.Name, strings.TrimSpace(ex.Task))

	fmt.Println("\nResources:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	r := ex.Resources
	row := func(kind, name string) { fmt.Fprintf(w, "  %s\t%s\t%s\n", kind, name, st.IDs[name]) }
	for _, v := range r.VPCs {
		row("vpc", v.Name)
	}
	for _, s := range r.Subnets {
		row("subnet", s.Name)
	}
	for _, g := range r.InternetGateways {
		row("internet gateway", g.Name)
	}
	for _, rt := range r.RouteTables {
		row("route table", rt.Name)
	}
	for _, sg := range r.SecurityGroups {
		row("security group", sg.Name)
	}
	for _, acl := range r.NetworkACLs {
		row("network ACL", acl.Name)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	addrs, err := exercise.Addresses(ctx, c, ex, st)
	if err != nil {
		return err
	}
	fmt.Println("\nInstances:")
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  name\tinstance ID\tstate\tprivate IP\tpublic IP\tshell")
	for _, in := range r.Instances {
		ad := addrs[in.Name]
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\tdocker exec -it %s bash\n",
			in.Name, st.IDs[in.Name], ad.State, show(ad.Private.IsValid(), ad.Private.String()), show(ad.Public.IsValid(), ad.Public.String()), ad.Container)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Println("\nThe operator box on the internet: docker exec -it vpcsim-operator bash")
	fmt.Println("When you are done: scripts/cap.sh verify. Stuck: scripts/cap.sh hint.")
	return nil
}

func show(ok bool, s string) string {
	if ok {
		return s
	}
	return "-"
}

func (a *app) verify(ctx context.Context) error {
	ex, st, err := a.current()
	if err != nil {
		return err
	}
	if !reconcilerRunning(ctx) {
		return errors.New("vpcsim is not running, so the network does not reflect your changes; start the lab with scripts/vpclab.sh up")
	}
	c, err := floci.EC2(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Waiting %s for vpcsim to apply your latest changes...\n\n", settle)
	time.Sleep(settle)
	results, err := exercise.Verify(ctx, c, ex, st)
	if err != nil {
		return err
	}
	passed := 0
	for _, r := range results {
		if r.Pass {
			passed++
			fmt.Printf("  PASS  %s\n", r.Check.Name)
		} else {
			fmt.Printf("  FAIL  %s\n        %s\n", r.Check.Name, r.Detail)
		}
	}
	fmt.Printf("\n%d of %d checks pass.\n", passed, len(results))
	if passed < len(results) {
		return errFailed
	}
	fmt.Println("Exercise solved. Remove its resources with scripts/cap.sh stop.")
	return nil
}

func (a *app) hint() error {
	ex, st, err := a.current()
	if err != nil {
		return err
	}
	if len(ex.Hints) == 0 {
		fmt.Println("This exercise has no hints.")
		return nil
	}
	if st.HintsShown < len(ex.Hints) {
		st.HintsShown++
		if err := exercise.SaveState(a.statePath, st); err != nil {
			return err
		}
	}
	for i := range st.HintsShown {
		fmt.Printf("Hint %d of %d: %s\n", i+1, len(ex.Hints), ex.Hints[i])
	}
	return nil
}

func (a *app) stop(ctx context.Context) error {
	ex, st, err := a.current()
	if err != nil {
		return err
	}
	c, err := floci.EC2(ctx)
	if err != nil {
		return err
	}
	if errs := exercise.Stop(ctx, c, st); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "warning:", e)
		}
	}
	if err := os.Remove(a.statePath); err != nil {
		return err
	}
	fmt.Printf("Removed %s. Resources you created yourself stay in Floci.\n", ex.Name)
	return nil
}

func (a *app) reset(ctx context.Context) error {
	_, st, err := a.current()
	if err != nil {
		return err
	}
	if err := a.stop(ctx); err != nil {
		return err
	}
	return a.start(ctx, st.Exercise)
}
