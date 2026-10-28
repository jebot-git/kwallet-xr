#pragma once
#include <string>
namespace dw {
inline const char* xml0 = R"DOME(<interface name="org.kde.KWallet">
    <signal name="walletListDirty">
    </signal>
    <signal name="walletCreated">
      <arg name="wallet" type="s" direction="out" />
    </signal>
    <signal name="walletOpened">
      <arg name="wallet" type="s" direction="out" />
    </signal>
    <signal name="walletAsyncOpened">
      <arg name="tId" type="i" direction="out" />
      <arg name="handle" type="i" direction="out" />
    </signal>
    <signal name="walletDeleted">
      <arg name="wallet" type="s" direction="out" />
    </signal>
    <signal name="walletClosed">
      <arg name="wallet" type="s" direction="out" />
    </signal>

    <signal name="walletClosed">
      <arg name="handle" type="i" direction="out" />
      <annotation name="org.freedesktop.DBus.Deprecated" value="true" />
    </signal>
    <signal name="walletClosedId">
      <arg name="handle" type="i" direction="out" />
    </signal>
    <signal name="allWalletsClosed">
    </signal>
    <signal name="folderListUpdated">
      <arg name="wallet" type="s" direction="out" />
    </signal>
    <signal name="folderUpdated">
      <arg type="s" direction="out" />
      <arg type="s" direction="out" />
    </signal>
    <signal name="applicationDisconnected">
      <arg name="wallet" type="s" direction="out" />
      <arg name="application" type="s" direction="out" />
    </signal>
    <method name="isEnabled">
      <arg type="b" direction="out" />
    </method>
    <method name="open">
      <arg type="i" direction="out" />
      <arg name="wallet" type="s" direction="in" />
      <arg name="wId" type="x" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="openAsync">
      <arg type="i" direction="out" />
      <arg name="wallet" type="s" direction="in" />
      <arg name="wId" type="x" direction="in" />
      <arg name="appid" type="s" direction="in" />
      <arg name="handleSession" type="b" direction="in" />
    </method>
    <method name="close">
      <arg type="i" direction="out" />
      <arg name="wallet" type="s" direction="in" />
      <arg name="force" type="b" direction="in" />
    </method>
    <method name="close">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="force" type="b" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="sync">
      <arg name="handle" type="i" direction="in" />
      <arg name="appid" type="s" direction="in" />
      <annotation name="org.freedesktop.DBus.Method.NoReply" value="true" />
    </method>
    <method name="deleteWallet">
      <arg type="i" direction="out" />
      <arg name="wallet" type="s" direction="in" />
    </method>
    <method name="isOpen">
      <arg type="b" direction="out" />
      <arg name="wallet" type="s" direction="in" />
    </method>
    <method name="isOpen">
      <arg type="b" direction="out" />
      <arg name="handle" type="i" direction="in" />
    </method>
    <method name="users">
      <arg type="as" direction="out" />
      <arg name="wallet" type="s" direction="in" />
    </method>
    <method name="changePassword">
      <arg name="wallet" type="s" direction="in" />
      <arg name="wId" type="x" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="wallets">
      <arg type="as" direction="out" />
    </method>
    <method name="folderList">
      <arg type="as" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="hasFolder">
      <arg type="b" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="createFolder">
      <arg type="b" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="removeFolder">
      <arg type="b" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="entryList">
      <arg type="as" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="readEntry">
      <arg type="ay" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="readMap">
      <arg type="ay" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="readPassword">
      <arg type="s" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="readEntryList">
      <arg type="a{sv}" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="QVariantMap" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
      <annotation name="org.freedesktop.DBus.Deprecated" value="true" />
    </method>
    <method name="entriesList">
      <arg type="a{sv}" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="QVariantMap" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="readMapList">
      <arg type="a{sv}" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="QVariantMap" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
      <annotation name="org.freedesktop.DBus.Deprecated" value="true" />
    </method>
    <method name="mapList">
      <arg type="a{sv}" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="QVariantMap" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="readPasswordList">
      <arg type="a{sv}" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="QVariantMap" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
      <annotation name="org.freedesktop.DBus.Deprecated" value="true" />
    </method>
    <method name="passwordList">
      <arg type="a{sv}" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="QVariantMap" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="renameEntry">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="oldName" type="s" direction="in" />
      <arg name="newName" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="writeEntry">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="value" type="ay" direction="in" />
      <arg name="entryType" type="i" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="writeEntry">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="value" type="ay" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="writeMap">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="value" type="ay" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="writePassword">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="value" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="hasEntry">
      <arg type="b" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="entryType">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="removeEntry">
      <arg type="i" direction="out" />
      <arg name="handle" type="i" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
      <arg name="appid" type="s" direction="in" />
    </method>
    <method name="disconnectApplication">
      <arg type="b" direction="out" />
      <arg name="wallet" type="s" direction="in" />
      <arg name="application" type="s" direction="in" />
    </method>
    <method name="reconfigure">
    </method>
    <method name="folderDoesNotExist">
      <arg type="b" direction="out" />
      <arg name="wallet" type="s" direction="in" />
      <arg name="folder" type="s" direction="in" />
    </method>
    <method name="keyDoesNotExist">
      <arg type="b" direction="out" />
      <arg name="wallet" type="s" direction="in" />
      <arg name="folder" type="s" direction="in" />
      <arg name="key" type="s" direction="in" />
    </method>
    <method name="closeAllWallets">
    </method>
    <method name="networkWallet">
      <arg type="s" direction="out" />
    </method>
    <method name="localWallet">
      <arg type="s" direction="out" />
    </method>
  </interface>
)DOME";
inline const char* xml1 = R"DOME(<interface name="org.kde.kwalletcompat">
        <method name="changePassword">
            <arg name="wallet" type="s" direction="in" />
            <arg name="wId" type="x" direction="in" />
            <arg name="appid" type="s" direction="in" />
        </method>
    </interface>
)DOME";
inline const char* xml2 = R"DOME(<interface name="org.freedesktop.Secret.Service">
		<property name="Collections" type="ao" access="read" />

		<method name="OpenSession">
			<arg name="algorithm" type="s" direction="in" />
			<arg name="input" type="v" direction="in" />
			<arg name="output" type="v" direction="out" />
			<arg name="result" type="o" direction="out" />
		</method>

		<method name="CreateCollection">
			<arg name="properties" type="a{sv}" direction="in" />
			<annotation name="org.qtproject.QtDBus.QtTypeName.In0" value="QVariantMap" />
			<arg name="alias" type="s" direction="in" />
			<arg name="collection" type="o" direction="out" />
			<arg name="prompt" type="o" direction="out" />
		</method>

		<method name="SearchItems">
			<arg name="attributes" type="a{ss}" direction="in" />
            <annotation name="org.qtproject.QtDBus.QtTypeName.In0" value="StrStrMap" />
			<arg name="unlocked" type="ao" direction="out" />
			<arg name="locked" type="ao" direction="out" />
		</method>

		<method name="Unlock">
			<arg name="objects" type="ao" direction="in" />
			<arg name="unlocked" type="ao" direction="out" />
			<arg name="prompt" type="o" direction="out" />
		</method>

		<method name="Lock">
			<arg name="objects" type="ao" direction="in" />
			<arg name="locked" type="ao" direction="out" />
			<arg name="Prompt" type="o" direction="out" />
		</method>

		<method name="GetSecrets">
			<arg name="items" type="ao" direction="in" />
			<arg name="session" type="o" direction="in" />
			<arg name="secrets" type="a{o(oayays)}" direction="out" />
			<annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="FreedesktopSecretMap" />
		</method>

		<method name="ReadAlias">
			<arg name="name" type="s" direction="in" />
			<arg name="collection" type="o" direction="out" />
		</method>

		<method name="SetAlias">
			<arg name="name" type="s" direction="in" />
			<arg name="collection" type="o" direction="in" />
		</method>

		<signal name="CollectionCreated">
			<arg name="collection" type="o" />
		</signal>

		<signal name="CollectionDeleted">
			<arg name="collection" type="o" />
		</signal>

		<signal name="CollectionChanged">
			<arg name="collection" type="o" />
		</signal>
	</interface>
)DOME";
inline const char* xml3 = R"DOME(<interface name="org.freedesktop.Secret.Collection">

		<property name="Items" type="ao" access="read" />
		<property name="Label" type="s" access="readwrite" />
		<property name="Locked" type="b" access="read" />
		<property name="Created" type="t" access="read" />
		<property name="Modified" type="t" access="read" />

		<method name="Delete">
			<arg name="prompt" type="o" direction="out" />
		</method>

		<method name="SearchItems">
			<arg name="attributes" type="a{ss}" direction="in" />
            <annotation name="org.qtproject.QtDBus.QtTypeName.In0" value="StrStrMap" />
			<arg name="results" type="ao" direction="out" />
		</method>

		<method name="CreateItem">
			<arg name="properties" type="a{sv}" direction="in" />
			<annotation name="org.qtproject.QtDBus.QtTypeName.In0" value="PropertiesMap" />
			<arg name="secret" type="(oayays)" direction="in" />
			<annotation name="org.qtproject.QtDBus.QtTypeName.In1" value="FreedesktopSecret" />
			<arg name="replace" type="b" direction="in" />
			<arg name="item" type="o" direction="out" />
			<arg name="prompt" type="o" direction="out" />
		</method>

		<signal name="ItemCreated">
			<arg name="item" type="o" />
		</signal>

		<signal name="ItemDeleted">
			<arg name="item" type="o" />
		</signal>

		<signal name="ItemChanged">
			<arg name="item" type="o" />
		</signal>
	</interface>
)DOME";
inline const char* xml4 = R"DOME(<interface name="org.freedesktop.Secret.Item">

		<property name="Locked" type="b" access="read" />

		<property name="Attributes" type="a{ss}" access="readwrite">
            <annotation name="org.qtproject.QtDBus.QtTypeName" value="StrStrMap" />
		</property>

		<property name="Label" type="s" access="readwrite" />

		<property name="Type" type="s" access="readwrite" />

		<property name="Created" type="t" access="read" />

		<property name="Modified" type="t" access="read" />

		<method name="Delete">
			<arg name="Prompt" type="o" direction="out" />
		</method>

		<method name="GetSecret">
			<arg name="session" type="o" direction="in" />
			<arg name="secret" type="(oayays)" direction="out" />
			<annotation name="org.qtproject.QtDBus.QtTypeName.Out0" value="FreedesktopSecret" />
		</method>

		<method name="SetSecret">
			<arg name="secret" type="(oayays)" direction="in" />
			<annotation name="org.qtproject.QtDBus.QtTypeName.In0" value="FreedesktopSecret" />
		</method>
	</interface>
)DOME";
inline const char* xml5 = R"DOME(<interface name="org.freedesktop.Secret.Prompt">

		<method name="Prompt">
			<arg name="window_id" type="s" direction="in" />
		</method>

		<method name="Dismiss">
		</method>


		<signal name="Completed">
			<arg name="dismissed" type="b" />
			<arg name="result" type="v" />
		</signal>
	</interface>
)DOME";
inline const char* xml6 = R"DOME(<interface name="org.freedesktop.Secret.Session">

		<method name="Close">
		</method>

	</interface>
)DOME";
inline const char* xml7 = R"DOME(<interface name="org.freedesktop.impl.portal.Secret">


    <method name="RetrieveSecret">
      <annotation name="org.gtk.GDBus.C.Name" value="retrieve_secret" />
      <annotation name="org.gtk.GDBus.C.UnixFD" value="true" />
      <arg type="o" name="handle" direction="in" />
      <arg type="s" name="app_id" direction="in" />
      <arg type="h" name="fd" direction="in" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.In3" value="QVariantMap" />
      <arg type="a{sv}" name="options" direction="in" />
      <arg type="u" name="response" direction="out" />
      <annotation name="org.qtproject.QtDBus.QtTypeName.Out1" value="QVariantMap" />
      <arg type="a{sv}" name="results" direction="out" />
    </method>
    <property name="version" type="u" access="read" />
  </interface>
)DOME";
inline std::string introspection(const std::string& path)
{
    std::string body;
    if (path == "/modules/kwalletd6")
        body = xml0;
    else if (path == "/ksecretd")
        body = xml1;
    else if (path == "/org/freedesktop/portal/desktop")
        body = xml7;
    else if (path == "/org/freedesktop/secrets")
        body = xml2;
    else if (path.find("/session/") != std::string::npos)
        body = xml6;
    else if (path.find("/prompt/") != std::string::npos)
        body = xml5;
    else if (path.find("/item/") != std::string::npos)
        body = xml4;
    else
        body = xml3;
    return "<node>" + body
        + "<interface name=\"org.freedesktop.DBus.Properties\"><method name=\"Get\"><arg type=\"s\" "
          "direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" direction=\"out\"/></method><method "
          "name=\"GetAll\"><arg type=\"s\" direction=\"in\"/><arg type=\"a{sv}\" direction=\"out\"/></method><method "
          "name=\"Set\"><arg type=\"s\" direction=\"in\"/><arg type=\"s\" direction=\"in\"/><arg type=\"v\" "
          "direction=\"in\"/></method><signal name=\"PropertiesChanged\"><arg type=\"s\"/><arg type=\"a{sv}\"/><arg "
          "type=\"as\"/></signal></interface></node>";
}
inline bool wallet_signature(const std::string& m, const std::string& s, bool compat)
{
    if (compat)
        return m == "changePassword" && s == "sxs";
    if (m == "isEnabled" && s == "")
        return true;
    if (m == "open" && s == "sxs")
        return true;
    if (m == "openAsync" && s == "sxsb")
        return true;
    if (m == "close" && s == "sb")
        return true;
    if (m == "close" && s == "ibs")
        return true;
    if (m == "sync" && s == "is")
        return true;
    if (m == "deleteWallet" && s == "s")
        return true;
    if (m == "isOpen" && s == "s")
        return true;
    if (m == "isOpen" && s == "i")
        return true;
    if (m == "users" && s == "s")
        return true;
    if (m == "changePassword" && s == "sxs")
        return true;
    if (m == "wallets" && s == "")
        return true;
    if (m == "folderList" && s == "is")
        return true;
    if (m == "hasFolder" && s == "iss")
        return true;
    if (m == "createFolder" && s == "iss")
        return true;
    if (m == "removeFolder" && s == "iss")
        return true;
    if (m == "entryList" && s == "iss")
        return true;
    if (m == "readEntry" && s == "isss")
        return true;
    if (m == "readMap" && s == "isss")
        return true;
    if (m == "readPassword" && s == "isss")
        return true;
    if (m == "readEntryList" && s == "isss")
        return true;
    if (m == "entriesList" && s == "iss")
        return true;
    if (m == "readMapList" && s == "isss")
        return true;
    if (m == "mapList" && s == "iss")
        return true;
    if (m == "readPasswordList" && s == "isss")
        return true;
    if (m == "passwordList" && s == "iss")
        return true;
    if (m == "renameEntry" && s == "issss")
        return true;
    if (m == "writeEntry" && s == "issayis")
        return true;
    if (m == "writeEntry" && s == "issays")
        return true;
    if (m == "writeMap" && s == "issays")
        return true;
    if (m == "writePassword" && s == "issss")
        return true;
    if (m == "hasEntry" && s == "isss")
        return true;
    if (m == "entryType" && s == "isss")
        return true;
    if (m == "removeEntry" && s == "isss")
        return true;
    if (m == "disconnectApplication" && s == "ss")
        return true;
    if (m == "reconfigure" && s == "")
        return true;
    if (m == "folderDoesNotExist" && s == "ss")
        return true;
    if (m == "keyDoesNotExist" && s == "sss")
        return true;
    if (m == "closeAllWallets" && s == "")
        return true;
    if (m == "networkWallet" && s == "")
        return true;
    if (m == "localWallet" && s == "")
        return true;
    return false;
}
inline bool secret_signature(const std::string& iface, const std::string& m, const std::string& s)
{
    if (iface == "org.freedesktop.Secret.Collection" && m == "Delete" && s == "")
        return true;
    if (iface == "org.freedesktop.Secret.Collection" && m == "SearchItems" && s == "a{ss}")
        return true;
    if (iface == "org.freedesktop.Secret.Collection" && m == "CreateItem" && s == "a{sv}(oayays)b")
        return true;
    if (iface == "org.freedesktop.Secret.Item" && m == "Delete" && s == "")
        return true;
    if (iface == "org.freedesktop.Secret.Item" && m == "GetSecret" && s == "o")
        return true;
    if (iface == "org.freedesktop.Secret.Item" && m == "SetSecret" && s == "(oayays)")
        return true;
    if (iface == "org.freedesktop.Secret.Prompt" && m == "Prompt" && s == "s")
        return true;
    if (iface == "org.freedesktop.Secret.Prompt" && m == "Dismiss" && s == "")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "OpenSession" && s == "sv")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "CreateCollection" && s == "a{sv}s")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "SearchItems" && s == "a{ss}")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "Unlock" && s == "ao")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "Lock" && s == "ao")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "GetSecrets" && s == "aoo")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "ReadAlias" && s == "s")
        return true;
    if (iface == "org.freedesktop.Secret.Service" && m == "SetAlias" && s == "so")
        return true;
    if (iface == "org.freedesktop.Secret.Session" && m == "Close" && s == "")
        return true;
    if (iface == "org.freedesktop.impl.portal.Secret" && m == "RetrieveSecret" && s == "osha{sv}")
        return true;
    if (iface == "org.freedesktop.DBus.Properties")
        return (m == "Get" && s == "ss") || (m == "GetAll" && s == "s") || (m == "Set" && s == "ssv");
    return false;
}

}
