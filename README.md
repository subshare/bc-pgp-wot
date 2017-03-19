OpenPGP/GnuPG web-of-trust (WOT)
===

This repository is dedicated to the OpenPGP/GnuPG web-of-trust. It currently contains one single
project/library: `org.bouncycastle.openpgp.wot`

Its feature set is in short **full compatibility with GnuPG's trust database**. In detail, this means:

1) Read GnuPG's `trustdb.gpg` (usually located in `~/.gnupg/`).

	a) Read the (previously calculated) validity of a key.

	b) Read key properties like "disabled" or "owner-trust".

2) Write GnuPG's `trustdb.gpg`.

	a) Set a key's "owner-trust".

	b) Set a key's "disabled" flag.

	c) Recalculate the validity of all public-keys.

	d) Create a new, fresh `trustdb.gpg`.

3) It contains a key registry and related data structure used to *efficiently* look up keys and their relations. This is needed by the
validity-calculation, but may be useful for other people, too.

	a) Look up a key by its ID.

	b) Look up a key by its fingerprint.

	c) Look up all keys that have been signed (a.k.a. certified) by a certain key (identified by ID or fingerprint).

	d) Get sub-keys of a master-key.

	e) Get master-key of a sub-key.

	f) Get certifications of a certain user-ID.

4) File abstraction: Both the trust-db and the key-registry can read/write data from/to any location. There's
already an implementation for `java.io.File` (for reading/writing GnuPG's data in `~/.gnupg/`), but people who
want to store key-rings and trust in a database might easily implement other persistence.

The following features are still missing:

1) Support trust models other than 'PGP'.

2) Remove entries from the `trustdb.gpg` - e.g. when a key was removed from the key ring(s).

3) Read configuration settings like "how many marginals are needed" from GnuPG (or any other?) configuration file.

I currently do *not* plan to implement these missing features, because they are IMHO not important at all. But
contributions from other developers are highly appreciated.


See also: [issue bc-java#119](https://github.com/bcgit/bc-java/pull/119/)


Gradle
===
Add this to your `build.gradle` to use this library:

	dependencies {
		compile group: 'org.bouncycastle', name: 'org.bouncycastle.openpgp.wot' , version: '1.56.1'
	}

	repositories {
		maven {
			url 'http://subshare.org/maven/release'
		}
		maven {
			url 'http://subshare.org/maven/snapshot'
		}
	}

Of course, you only need the "release"-repository and can omit the "snapshot"-repo, if you do *not* want
to include a "-SNAPSHOT"-version.


Maven
===
Add this to your `pom.xml` to use this library:

	<dependencies>
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>org.bouncycastle.openpgp.wot</artifactId>
			<version>1.56.1</version>
		</dependency>
	</dependencies>

	<repositories>
		<repository>
			<id>subshare</id>
			<url>http://subshare.org/maven/release</url>
			<releases>
				<enabled>true</enabled>
			</releases>
			<snapshots>
				<enabled>false</enabled>
			</snapshots>
		</repository>
		<repository>
			<id>subshare</id>
			<url>http://subshare.org/maven/snapshot</url>
			<releases>
				<enabled>false</enabled>
			</releases>
			<snapshots>
				<enabled>true</enabled>
			</snapshots>
		</repository>
	</repositories>

Like already mentioned for Gradle above: You can omit the "snapshot" repository, if you do *not* want to
include a "-SNAPSHOT"-version in your project.


Jenkins + manual download
===
The project is built [by our Jenkins here](https://codewizards.co/jenkins/job/org.bouncycastle.openpgp.wot/)
and the library can be manually downloaded from it, too. It is however urgently recommended to use a modern build
tool like Gradle or Maven.
