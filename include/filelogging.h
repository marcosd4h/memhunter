#pragma once

#include "common.h"

namespace GeneralHelpers
{

	class FileLogging
	{
	public:
		enum VerbosityLevel
		{
			LVLUNKNOWN = 0,
			LVLFATAL,
			LVLERROR,
			LVLWARN,
			LVLINFO,
			LVLDEBUG
		};

		static inline const char* VerbosityModeToString(VerbosityLevel mode)
		{
			switch (mode)
			{
				case LVLUNKNOWN:	return " - Verbosity UNKNOWN - ";
				case LVLFATAL:		return " - Verbosity FATAL - ";
				case LVLERROR:		return " - Verbosity ERROR - ";
				case LVLWARN:		return " - Verbosity WARNING - ";
				case LVLINFO:		return " - Verbosity INFO - ";
				case LVLDEBUG:		return " - Verbosity DEBUG - ";
			}
		}

		static FileLogging& Instance()
		{
			static FileLogging logger;
			return logger;
		}

		bool Initialize(const VerbosityLevel mode, const std::string &targetFileName)
		{
			bool ret = false;

			m_loggingFile.open(targetFileName.c_str(), std::ios::out | std::ios::app);
			
			if (m_loggingFile.good())
			{
				m_initialized = true;
				m_workingMode = mode;
			}
			else
			{
				m_initialized = false;
				m_workingMode = LVLUNKNOWN;
			}

			return ret;			
		}

		void ChangeVerbosityMode(const VerbosityLevel mode)
		{
			m_workingMode = mode;
		}

		void Log(const VerbosityLevel mode, const char* fmt, ...)
		{
			if ((m_initialized) && (m_workingMode != LVLUNKNOWN) && (mode >= m_workingMode))
			{
				va_list varArgs;
				va_start(varArgs, fmt);
				InternalLoggingTrace(m_workingMode, fmt, varArgs);
				va_end(varArgs);				
			}
		}

	private:

		void InternalLoggingTrace(const VerbosityLevel mode, const char* fmt, va_list varArgs)
		{
			static const unsigned int MAX_NUMBER_OF_TIME_DATA = 512;
			static const unsigned int MAX_NUMBER_OF_VAR_DATA = 2048;
			static const unsigned int MAX_NUMBER_OF_LOGGING_BUFFER = 4096;

			if (m_initialized && (m_loggingFile.good()))
			{
				char variableBuffer[MAX_NUMBER_OF_VAR_DATA] = { 0 };
				char finalMessage[MAX_NUMBER_OF_LOGGING_BUFFER] = { 0 };
				char timeData[MAX_NUMBER_OF_TIME_DATA] = { 0 };

				// Get timestamp with milliseconds
				time_t rawtime = { 0 };
				struct tm timeinfo = { 0 };
				unsigned int millisecs = 0;
				localtime_s(&timeinfo, &rawtime);

				//getting millisecs and round it to near sec
				millisecs = lrint(timeinfo.tm_sec / 1000.0);
				if (millisecs >= 1000)
				{
					millisecs -= 1000;
					timeinfo.tm_sec++;
				}

				//Getting timestamp
				std::strftime(timeData, MAX_NUMBER_OF_TIME_DATA, "%Y-%m-%d %H:%M:%S", &timeinfo);
				snprintf(timeData, (MAX_NUMBER_OF_TIME_DATA - strlen(timeData)), "%s:%d", timeData, millisecs);

				// Format message
				vsprintf_s(variableBuffer, MAX_NUMBER_OF_VAR_DATA, fmt, varArgs);
				sprintf_s(finalMessage, MAX_NUMBER_OF_LOGGING_BUFFER, "%s %-12s %s", timeData, VerbosityModeToString(mode), variableBuffer);

				//Output logging
				m_loggingFile << variableBuffer << std::endl;
			}
		}

		FileLogging() : m_initialized(false), m_workingMode(LVLUNKNOWN){}
		~FileLogging() 
		{
			if (m_loggingFile.good())
			{
				m_loggingFile << std::endl;
				m_loggingFile.close();
			}
		}

		FileLogging(const FileLogging&) = delete;
		FileLogging& operator = (const FileLogging&) = delete;

		//Private vars
		bool m_initialized;
		VerbosityLevel m_workingMode;
		std::ofstream m_loggingFile;
	};
}
