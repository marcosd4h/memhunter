#pragma once

//General
#include <algorithm>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cctype>
#include <cwctype>
#include <locale>
#include <cctype>
#include <mutex>
#include <exception>
#include <typeinfo>
#include <stdexcept>
#include <ctime>
#include <vector>
#include <queue>
#include <memory>
#include <vector>
#include <map>
#include <iterator>
#include <iomanip>
#include <fstream>
#include <cstdarg>
#include <ctime>
#include <cstdio>
#include "windows.h"
#include "stdio.h"
#include "stdarg.h"
#include "tlhelp32.h"
#include "versionhelpers.h"
#include "tchar.h"
#include "Shlobj.h"
#include "dbghelp.h"
#include "psapi.h"
#include "Winternl.h"
#include "wincrypt.h"
#include "wintrust.h"
#include "softpub.h"

//Blackbone includes
#include <BlackBone/Config.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/Process/MultPtr.hpp>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/PE/PEImage.h>
#include <BlackBone/Misc/Utils.h>
#include <BlackBone/Misc/DynImport.h>
#include <BlackBone/Syscalls/Syscall.h>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Asm/LDasm.h>
#include <BlackBone/localHook/VTableHook.hpp>
#include <BlackBone/Patterns/PatternSearch.h>
#include <BlackBone/Process/RPC/RemoteFunction.hpp>
#include <BlackBone/Syscalls/Syscall.h>

//Common
#include "tokenutils/tokenutils.h"
#include "cmdparser.h"
#include "filelogging.h"
#include "customtypes.h"
#include "helpers.h"
#include "json.h"
#include "customtypes.h"
#include "hunter.h"
#include "helpers.h"
#include "configmanager.h"
#include "huntersmanager.h"
#include "reportmanager.h"
#include "servicemanager.h"
#include "huntersorchestration.h"

//Hunters
#include "suspiciousmodules.h"
#include "suspiciousthreads.h"
#include "suspiciousregions.h"
#include "suspiciouscallstack.h"
#include "suspiciousexports.h"
#include "suspiciousregistrypersistence.h"
#include "suspicioushollowedmodules.h"
#include "suspiciousparents.h"
#include "suspiciousshellcode.h"



