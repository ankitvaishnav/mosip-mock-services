package io.mosip.proxy.abis.service;

import io.mosip.proxy.abis.entity.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface ProxyAbisInsertService {
	

	
	public void deleteData(String referenceId);

	public void insertData(InsertRequestMO ie);
	
	public IdentityResponse findDupication(IdentityRequest ir);
	
	public String saveUploadedFileWithParameters(MultipartFile upoadedFile, String alias,
			String password,String keystore) ;

	//TODO changes by AV
	public String fetchCBEFF(String url) throws Exception;
}
