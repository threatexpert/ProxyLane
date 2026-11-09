/* A bounded event-loop pump for a shared session, including when no channel
 * is being read. Public libssh2 channel APIs otherwise leave keepalive replies
 * unread on an idle session. This is the only dependency on private libssh2
 * APIs; the source version is pinned by build-ssh.ps1. */
#include "libssh2_priv.h"
#include "transport.h"

__declspec(dllexport) int plssh_pump(LIBSSH2_SESSION *session)
{
    int i, rc;
    for(i = 0; i < 32; ++i) {
        rc = _libssh2_transport_read(session);
        if(rc == LIBSSH2_ERROR_EAGAIN || rc == 0) return 0;
        if(rc < 0) return rc;
    }
    return 1; /* Work remains: yield before another batch. */
}
