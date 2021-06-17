package io.mosip.proxy.abis.service;

import io.mosip.proxy.abis.entity.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

public interface ProxyAbisInsertService {
	

	
	public void deleteData(String referenceId);

	public int insertData(InsertRequestMO ie);
	
	public IdentifyDelayResponse findDuplication(IdentityRequest ir);
	
	public String saveUploadedFileWithParameters(MultipartFile upoadedFile, String alias,
			String password,String keystore) ;

	public Boolean getDuplicate();
	public void setDuplicate(Boolean d);

	public Map<String, Expectation> getExpectations();

	public void setExpectation(Expectation exp);

	public void deleteExpectation(String id);
}
