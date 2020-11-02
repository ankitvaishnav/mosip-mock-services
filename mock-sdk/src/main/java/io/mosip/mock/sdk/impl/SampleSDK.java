package io.mosip.mock.sdk.impl;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.mosip.mock.sdk.dto.*;
import io.mosip.mock.sdk.utils.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import io.mosip.kernel.biometrics.constant.BiometricFunction;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.Match;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.model.Decision;
import io.mosip.kernel.biometrics.model.MatchDecision;
import io.mosip.kernel.biometrics.model.QualityCheck;
import io.mosip.kernel.biometrics.model.QualityScore;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.kernel.biometrics.model.SDKInfo;
import io.mosip.kernel.biometrics.spi.IBioApi;
import io.mosip.mock.sdk.constant.ResponseStatus;

/**
 * The Class BioApiImpl.
 * 
 * @author Sanjay Murali
 * @author Manoj SP
 * 
 */
@Component
public class SampleSDK implements IBioApi {

	Logger LOGGER = LoggerFactory.getLogger(SampleSDK.class);

	private static final String API_VERSION = "0.9";
	private static final boolean rest = true;
	private static final String host = "http://localhost:9099/";

	@Override
	public SDKInfo init(Map<String, String> initParams) {
		InitRequestDto initRequestDto = new InitRequestDto();
		initRequestDto.setInitParams(initParams);
		ResponseEntity<?> responseEntity = Util.restRequest(host+"init", HttpMethod.POST, MediaType.APPLICATION_JSON, initRequestDto, null, Response.class);
		Response<SDKInfo> response = (Response<SDKInfo>) responseEntity.getBody();
		return response.getResponse();
	}

	@Override
	public Response<QualityCheck> checkQuality(BiometricRecord sample, List<BiometricType> modalitiesToCheck, Map<String, String> flags) {
		CheckQualityRequestDto checkQualityRequestDto = new CheckQualityRequestDto();
		checkQualityRequestDto.setSample(sample);
		checkQualityRequestDto.setModalitiesToCheck(modalitiesToCheck);
		checkQualityRequestDto.setFlags(flags);
		ResponseEntity<?> responseEntity = Util.restRequest(host+"check-quality", HttpMethod.POST, MediaType.APPLICATION_JSON, checkQualityRequestDto, null, Response.class);
		Response<QualityCheck> response = (Response<QualityCheck>) responseEntity.getBody();
		return response;
	}

	@Override
	public Response<MatchDecision[]> match(BiometricRecord sample, BiometricRecord[] gallery,
			List<BiometricType> modalitiesToMatch, Map<String, String> flags) {
		MatchRequestDto matchRequestDto = new MatchRequestDto();
		matchRequestDto.setSample(sample);
		matchRequestDto.setGallery(gallery);
		matchRequestDto.setModalitiesToMatch(modalitiesToMatch);
		matchRequestDto.setFlags(flags);
		ResponseEntity<?> responseEntity = Util.restRequest(host+"match", HttpMethod.POST, MediaType.APPLICATION_JSON, matchRequestDto, null, Response.class);
		Response<MatchDecision[]> response = (Response<MatchDecision[]>) responseEntity.getBody();
		return response;
	}

	@Override
	public Response<BiometricRecord> extractTemplate(BiometricRecord sample, List<BiometricType> modalitiesToExtract, Map<String, String> flags) {
		ExtractTemplateRequestDto extractTemplateRequestDto = new ExtractTemplateRequestDto();
		extractTemplateRequestDto.setSample(sample);
		extractTemplateRequestDto.setModalitiesToExtract(modalitiesToExtract);
		extractTemplateRequestDto.setFlags(flags);
		ResponseEntity<?> responseEntity = Util.restRequest(host+"extract-template", HttpMethod.POST, MediaType.APPLICATION_JSON, extractTemplateRequestDto, null, Response.class);
		Response<BiometricRecord> response = (Response<BiometricRecord>) responseEntity.getBody();
		return response;
	}

	@Override
	public Response<BiometricRecord> segment(BiometricRecord biometricRecord, List<BiometricType> modalitiesToSegment, Map<String, String> flags) {
		SegmentRequestDto segmentRequestDto = new SegmentRequestDto();
		segmentRequestDto.setSample(biometricRecord);
		segmentRequestDto.setModalitiesToSegment(modalitiesToSegment);
		segmentRequestDto.setFlags(flags);
		ResponseEntity<?> responseEntity = Util.restRequest(host+"segment", HttpMethod.POST, MediaType.APPLICATION_JSON, segmentRequestDto, null, Response.class);
		Response<BiometricRecord> response = (Response<BiometricRecord>) responseEntity.getBody();
		return response;
	}

	@Override
	public BiometricRecord convertFormat(BiometricRecord sample, String sourceFormat, String targetFormat,
			Map<String, String> sourceParams, Map<String, String> targetParams, List<BiometricType> modalitiesToConvert) {
		ConvertFormatRequestDto convertFormatRequestDto = new ConvertFormatRequestDto();
		convertFormatRequestDto.setSample(sample);
		convertFormatRequestDto.setSourceFormat(sourceFormat);
		convertFormatRequestDto.setTargetFormat(targetFormat);
		convertFormatRequestDto.setSourceParams(sourceParams);
		convertFormatRequestDto.setTargetParams(targetParams);
		convertFormatRequestDto.setModalitiesToConvert(modalitiesToConvert);
		ResponseEntity<?> responseEntity = Util.restRequest(host+"convert-format", HttpMethod.POST, MediaType.APPLICATION_JSON, convertFormatRequestDto, null, Response.class);
		Response<BiometricRecord> response = (Response<BiometricRecord>) responseEntity.getBody();
		return response.getResponse();
	}


}