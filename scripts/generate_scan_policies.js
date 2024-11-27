// This is a ZAP standalone script - it will only run in ZAP.
// It generates the scan policies for https://github.com/zaproxy/zap-extensions/tree/main/addOns/scanpolicies etc
// The policies are created after starting a ZAP weekly release with the '-addoninstallall' option.

// Change the DIR below to match the local directory containing the alert files
var LIST_FILE = ROOT + "list.txt";

var FileWriter = Java.type('java.io.FileWriter');
var PrintWriter = Java.type('java.io.PrintWriter');
var PolicyTag = Java.type ('org.zaproxy.addon.commonlib.PolicyTag')
var extAscan = control.getExtensionLoader().getExtension(org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

var whatPolicy = "POLICY_SEQUENCE";
var includeNames = false;

var plugins = extAscan
  .getPolicyManager()
  .getDefaultScanPolicy()
  .getPluginFactory()
  .getAllPlugin()
  .toArray()
  .sort(function(a, b){return a.getId() - b.getId()});

// Dump out the plugin IDs
var fw = new FileWriter(LIST_FILE);
var pw = new PrintWriter(fw);
for (var i = 0; i < plugins.length; i++) {
  try {
    if (plugins[i].getAlertTags() != null && plugins[i].getAlertTags().keySet().contains(whatPolicy)) {
      if (includeNames) {
        pw.println(plugins[i].getId() + "\t" + plugins[i].getName());
      } else {
        pw.println(plugins[i].getId());
      }
    }
  } catch (e) {
    print(e);
  }
  pw.close();
}
