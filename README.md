# Exousia

Eclipse Exousia implements [Jakarta Authorization 2.1](https://jakarta.ee/specifications/authorization/2.1/), a technology that provides a low-level SPI for authorization modules, which are repositories of permissions facilitating subject based security by determining whether a given subject has a given permission, and algorithms to transform security constraints for specific containers (such as Jakarta Servlet or Jakarta Enterprise Beans) into these permissions

[Website](https://eclipse-ee4j.github.io/exousia)

Building
--------

Exousia can be built by executing the following from the project root:

``mvn clean package``

