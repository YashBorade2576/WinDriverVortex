#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <search.hpp>


plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,
    plugin_init,
    plugin_term,
    plugin_run,
    "Driver Vulnerability Analyzer",
    "Driver Vuln Analyzer",
    "DriverAnalyzer",
    "Ctrl-Alt-D"
};


struct VulnerabilityPattern {
    const char* name;
    const char* pattern;
    const char* description;
    int severity;
};

static VulnerabilityPattern patterns[] = {
    {"Stack Buffer Overflow", "E8??????0083C4", "Potential stack-based buffer overflow", 4},
    {"Heap Overflow", "FF15??????0083C8FF", "Heap memory corruption", 4},
    {"Use After Free", "8B08FF51??8BF085F6", "Use after free vulnerability", 5},
    {"Double Free", "FF15??????0083C408", "Double free detection", 5},
    {"Integer Overflow", "0FAF??83C8FF", "Integer overflow/underflow", 3},
    {"Null Pointer Dereference", "8B00FF50??85C0", "Null pointer dereference", 3},
    {"Uninitialized Memory", "8D85??FFFFFF50", "Uninitialized memory usage", 3},
    {"Race Condition", "FF15??????0083F8FF", "Potential race condition", 4},
    {"IOCTL Handler Issues", "8B450850E8??????0083C404", "Insecure IOCTL handling", 4},
    {"Memory Disclosure", "8B450C50E8??????0083C404", "Memory disclosure vulnerability", 3}
};


struct VulnerabilityResult {
    qstring functionName;
    qstring patternName;
    qstring description;
    ea_t address;
    int severity;
    qstring evidence;
};

std::vector<VulnerabilityResult> g_results;


bool analyze_buffer_overflow(ea_t ea) {
    insn_t cmd;
    if (decode_insn(&cmd, ea)) {

        if (cmd.itype == NN_call) {
            char buf[MAXSTR];
            get_func_name(cmd.ops[0].addr, buf, sizeof(buf));
            qstring funcName(buf);
            
            if (funcName.find("strcpy") != qstring::npos ||
                funcName.find("strcat") != qstring::npos ||
                funcName.find("gets") != qstring::npos ||
                funcName.find("sprintf") != qstring::npos) {
                return true;
            }
        }
    }
    return false;
}


bool analyze_ioctl_handler(ea_t ea) {
    segment_t* seg = getseg(ea);
    if (seg && seg->type == SEG_CODE) {
        insn_t cmd;
        if (decode_insn(&cmd, ea)) {

            if (cmd.itype == NN_mov && cmd.ops[1].type == o_reg) {

                char buf[MAXSTR];
                get_name(cmd.ops[0].addr, buf, sizeof(buf));
                if (strstr(buf, "IOCTL") || strstr(buf, "DeviceControl")) {
                    return true;
                }
            }
        }
    }
    return false;
}


void perform_vulnerability_analysis() {
    g_results.clear();
    
    msg("Starting driver vulnerability analysis...\n");
    
    for (ea_t ea = get_inf_structure().start_ea; ea < get_inf_structure().end_ea; ea = next_head(ea, BADADDR)) {

        if (analyze_buffer_overflow(ea)) {
            VulnerabilityResult result;
            result.address = ea;
            result.patternName = "Buffer Overflow";
            result.description = "Unsafe string operation detected";
            result.severity = 4;
            
            char buf[MAXSTR];
            get_name(ea, buf, sizeof(buf));
            result.evidence = buf;
            
            get_func_name(ea, buf, sizeof(buf));
            result.functionName = buf;
            
            g_results.push_back(result);
        }
        

        if (analyze_ioctl_handler(ea)) {
            VulnerabilityResult result;
            result.address = ea;
            result.patternName = "IOCTL Handler Issue";
            result.description = "Potential insecure IOCTL handling";
            result.severity = 4;
            
            char buf[MAXSTR];
            get_name(ea, buf, sizeof(buf));
            result.evidence = buf;
            
            get_func_name(ea, buf, sizeof(buf));
            result.functionName = buf;
            
            g_results.push_back(result);
        }
        

        for (const auto& pattern : patterns) {
            ea_t found_ea = bin_search(ea, get_inf_structure().end_ea, 
                                     pattern.pattern, NULL, 0, BIN_SEARCH_FORWARD);
            if (found_ea != BADADDR) {
                VulnerabilityResult result;
                result.address = found_ea;
                result.patternName = pattern.name;
                result.description = pattern.description;
                result.severity = pattern.severity;
                
                char buf[MAXSTR];
                get_name(found_ea, buf, sizeof(buf));
                result.evidence = buf;
                
                get_func_name(found_ea, buf, sizeof(buf));
                result.functionName = buf;
                
                g_results.push_back(result);
                ea = found_ea;
                break;
            }
        }
    }
    
    msg("Analysis completed. Found %d potential vulnerabilities.\n", g_results.size());
}


int plugin_init(void) {
    msg("Driver Vulnerability Analyzer Plugin Loaded\n");
    return PLUGIN_OK;
}


void plugin_term(void) {
    msg("Driver Vulnerability Analyzer Plugin Unloaded\n");
}


bool plugin_run(size_t arg) {
    perform_vulnerability_analysis();
    

    if (!g_results.empty()) {
        msg("\n=== VULNERABILITY ANALYSIS RESULTS ===\n");
        for (const auto& result : g_results) {
            msg("[%s] 0x%08X - %s: %s (Severity: %d)\n",
                result.functionName.c_str(),
                result.address,
                result.patternName.c_str(),
                result.description.c_str(),
                result.severity);
        }
    }
    
    return true;
}
