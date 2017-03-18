# bc-pgp-wot
OpenPGP/GnuPG WOT (web of trust)
===

This repository is dedicated to the OpenPGP/GnuPG web-of-trust. See [issue bc-java#119](https://github.com/bcgit/bc-java/pull/119/).

Gradle
===
Add this to your `build.gradle` to use this library:

	dependencies {
		compile group: 'org.bouncycastle', name: 'org.bouncycastle.openpgp.wot' , version: '1.56.0'
	}

	repositories {
		maven {
			url 'http://subshare.org/maven/snapshot'
		}
		maven {
			url 'http://subshare.org/maven/release'
		}
	}

Maven
===
Add this to your `pom.xml` to use this library:

	<dependencies>
		<dependency>
			<groupId>org.bouncycastle</groupId>
			<artifactId>org.bouncycastle.openpgp.wot</artifactId>
			<version>1.56.0</version>
		</dependency>
	</dependencies>

	<repositories>
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
	</repositories>
