// This is a ZAP standalone script - it will only run in ZAP.
// It generates the scan policies for https://github.com/zaproxy/zap-extensions/tree/main/addOns/scanpolicies etc
// The policies are created after starting a ZAP weekly release with the '-addoninstallall' option.

// Change the DIR below to match the local directory containing the alert files
var POLICY_FILE = "/zap/wrk/API.policy";

var FileWriter = Java.type('java.io.FileWriter');
var PrintWriter = Java.type('java.io.PrintWriter');
var PolicyTag = Java.type ('org.zaproxy.addon.commonlib.PolicyTag')
var extAscan = control.getExtensionLoader().getExtension(org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

var whatPolicy = "POLICY_API";

var plugins = extAscan
  .getPolicyManager()
  .getDefaultScanPolicy()
  .getPluginFactory()
  .getAllPlugin()
  .toArray()
  .sort(function(a, b){return a.getId() - b.getId()});

// Dump out the plugin IDs
var fw = new FileWriter(POLICY_FILE);
var pw = new PrintWriter(fw);

pw.println("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>");
pw.println("<configuration>");
pw.println("    <policy>Sequence</policy>");
pw.println("    <scanner>");
pw.println("        <level>OFF</level>");
pw.println("        <strength>MEDIUM</strength>");
pw.println("    </scanner>");
pw.println("    <plugins>");

for (var i = 0; i < plugins.length; i++) {
  try {
    if (plugins[i].getAlertTags() != null && plugins[i].getAlertTags().keySet().contains(whatPolicy)) {
      pw.println("            <p" + plugins[i].getId() + ">");
      pw.println("                <name>" + plugins[i].getName() + "</name>");
      pw.println("                <enabled>true</enabled>");
      pw.println("                <level>MEDIUM</level>");
      pw.println("            <p" + plugins[i].getId() + ">");
    }
  } catch (e) {
    print(e);
  }
}
pw.println("    </plugins>");
pw.println("<configuration>");
pw.close();
