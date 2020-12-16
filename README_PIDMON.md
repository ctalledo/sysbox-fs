This branch contains a sysbox-fs change that fixes the problem
described here:

https://github.com/nestybox/sysbox-internal/issues/542


Basically, `docker exec <container> sh -c "program &"` fails when `program`
calls a sysbox emulated syscall (e.g., mount, chown, etc). The reason is
described in the above issue.

One valid work-around is to use `docker exec -d <container> sh -c "program"`
instead. However, I felt users would fall into this problem in the field,
so I tried to implement a proper fix that did not rely on the work-around.

This branch contains this fix. However, the fix uses the `psnotify` go-lang
package, which in turn uses the kernel's `netlink` mechanism to track forking of
processes inside a sysbox container. This works fine when sysbox is running at
host level, but does not work when sysbox runs inside a privileged container
(e.g., the test container). The reason is that it appears the netlink mechanism
used by psnotify can only be used from the host's network namespace; using it
from another network namespace results in "permission denied".

This makes the fix non-viable, since it can't be tested as part of our
regression suite, and since it will not work for users that run sysbox inside a
privileged container (e.g., Coder).

As a side note, if we deploy the privileged container with `--network=host`, then
things work, but this has the potential to mess up the host's network config
so it's not good.

Also, it's not clear what performance impact this fix will have, given that it
make sysbox-fs work with the kernel to track forks for every process inside
every sys container. This can be costly. In addition, if sysbox-fs does not
process the kernel fork notifications fast enough, the kernel may drop some of
these, which is also functionally problematic.

Given that we have a simple work-around, and that the fix is a bit complex, I am
archiving this fix for now. We can revisit if and when we think it's truly
necessary.
