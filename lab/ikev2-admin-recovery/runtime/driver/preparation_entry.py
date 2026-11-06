"""Original preparation execution under the fresh admitted owner boundary.

The bootstrap supplies an admitted Owner, pinned body bytes and private Endpoint.
No CLI fallback can start the historical unowned preparation path.
"""
from admin_recovery import run_preparation, require, sha


def execute(owner, body_bytes, expected_sha256, source_path, endpoint, setup=None):
    namespace = owner.resources
    code=[]
    def initialize(resources):
        require(sha(body_bytes) == expected_sha256, 'Reviewed preparation body binding')
        require(owner.state == 'SETUP', 'Original preparation already entered')
        owner.journal.admission.revalidate()
        require('administrative_owner' not in namespace, 'Preparation namespace already entered')
        namespace.update(administrative_owner=owner, __name__='__preparation_owned__',__file__=str(source_path))
        code.append(compile(body_bytes,str(source_path),'exec'))
        if setup is not None:setup(resources)
    # Namespace remains in the original Owner even if setup fails before Stage,
    # or a nested finally raises. No body/finalizer replay on endpoint requests.
    def body(resources):
        resources['bodyEntered']=True
        exec(code[0], resources)
        failure = resources.get('failure')
        require(failure is None or not failure.event.is_set(), 'Sticky preparation failure')
    def finalize(resources):
        resident=resources.get('resident')
        if resident is not None:
            resident.finish(resident.close_session())
        for original in resources.get('operationOwners',{}).values():
            original.administrative_closure()
    return run_preparation(owner, initialize, body,finalize,endpoint)
