#pragma once

#include "common.h"

class HuntingDB
{
public:
	static HuntingDB& GetInstance()
	{
		static HuntingDB instance;
		if (!instance.IsInitialized())
		{
			instance.InitializeDB();
		}
		return instance;
	}

	bool InitializeDB(const std::wstring &dbname = CustomDefs::DEFAULT_DB_NAME);
	bool IsInitialized();

	bool AddUpdateRemoteProcess(const HunterCommon::ETWRemoteProcessData &data);
	bool AddUpdateRemoteThread(const HunterCommon::ETWRemoteThreadData &data);
	bool AddUpdateRemoteAlloc(const HunterCommon::ETWRemoteAllocData &data);

private:
	HuntingDB::HuntingDB() : m_ptrHuntingDB(nullptr) { }


	std::wstring m_DBFile;
	sqlite::database *m_ptrHuntingDB;
};
