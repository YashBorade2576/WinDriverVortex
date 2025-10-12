#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include "vulnerability_detector.h"

VulnerabilityDetector* g_vulnerabilityDetector = nullptr;

int plugin_init(void)
{
    if (ph.id != PLFM_386)
    {
        return PLUGIN_SKIP;
    }
    
    msg("DriverVulnHunter IDA Plugin initialized\n");
    g_vulnerabilityDetector = new VulnerabilityDetector();
    
    return PLUGIN_OK;
}

void plugin_term(void)
{
    if (g_vulnerabilityDetector)
    {
        delete g_vulnerabilityDetector;
        g_vulnerabilityDetector = nullptr;
    }
    
    msg("DriverVulnHunter IDA Plugin terminated\n");
}

bool plugin_run(size_t argument)
{
    if (!g_vulnerabilityDetector)
    {
        warning("Vulnerability detector not initialized");
        return false;
    }
    
    g_vulnerabilityDetector->ScanForVulnerabilities();
    auto results = g_vulnerabilityDetector->GetResults();
    
    if (results.empty())
    {
        info("No vulnerabilities detected in the current binary");
    }
    else
    {
        msg("\n=== DRIVER VULNERABILITY ANALYSIS RESULTS ===\n");
        
        for (const auto& result : results)
        {
            msg("[%s] Severity %d at 0x%08X: %s - %s\n",
                result.functionName.c_str(),
                result.severity,
                result.address,
                result.vulnerabilityType.c_str(),
                result.description.c_str());
        }
        
        msg("=== ANALYSIS COMPLETE - %d FINDINGS ===\n", results.size());
        
        std::string summaryMessage = "Analysis found " + std::to_string(results.size()) + " potential vulnerabilities";
        info(summaryMessage.c_str());
    }
    
    return true;
}

char comment[] = "Driver Vulnerability Analyzer Plugin";
char help[] = "This plugin analyzes Windows drivers for security vulnerabilities\n"
              "Hotkey: Ctrl-Alt-D\n"
              "Usage: Load a driver and run the plugin from Edit > Plugins menu";

char plugin_name[] = "DriverVulnHunter";
char plugin_hotkey[] = "Ctrl-Alt-D";

extern "C" plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,
    plugin_init,
    plugin_term, 
    plugin_run,
    comment,
    help,
    plugin_name,
    plugin_hotkey
};
