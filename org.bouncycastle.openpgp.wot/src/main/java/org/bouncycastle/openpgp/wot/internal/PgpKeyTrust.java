package org.bouncycastle.openpgp.wot.internal;

import static java.util.Objects.*;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.wot.key.PgpKey;
import org.bouncycastle.openpgp.wot.key.PgpKeyFingerprint;
import org.bouncycastle.openpgp.wot.key.PgpUserId;
import org.bouncycastle.openpgp.wot.key.PgpUserIdNameHash;

class PgpKeyTrust
{
    private final PgpKey pgpKey;
    private final Map<PgpUserIdNameHash, PgpUserIdTrust> nameHash2UserIdTrust = new HashMap<>();

    public PgpKeyTrust(final PgpKey pgpKey)
    {
        this.pgpKey = requireNonNull(pgpKey, "pgpKey");
    }

    public PgpKey getPgpKey()
    {
        return pgpKey;
    }

    public PgpKeyFingerprint getPgpKeyFingerprint()
    {
        return pgpKey.getPgpKeyFingerprint();
    }

    public PgpUserIdTrust getPgpUserIdTrust(final PgpUserId pgpUserId)
    {
        requireNonNull(pgpUserId, "pgpUserId");
        PgpUserIdTrust pgpUserIdTrust = nameHash2UserIdTrust.get(pgpUserId.getNameHash());
        if (pgpUserIdTrust == null)
        {
            pgpUserIdTrust = new PgpUserIdTrust(this, pgpUserId);
            nameHash2UserIdTrust.put(pgpUserId.getNameHash(), pgpUserIdTrust);
        }
        return pgpUserIdTrust;
    }

    public Collection<PgpUserIdTrust> getPgpUserIdTrusts()
    {
        return Collections.unmodifiableCollection(nameHash2UserIdTrust.values());
    }
}
