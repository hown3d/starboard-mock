# starboard-mock
This repository is an example for using starboard scanning with non existing workloads.

It's useful regarding scanning other kinds of clusters which are not in the Kubernetes ecosystem.

All communication regarding the needed pod is filtered out of the starboard source code.
Kubernetes API would otherwise complain that the pod/namespace doesn't exist.
