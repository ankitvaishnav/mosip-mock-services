# Mock SDK

## API signatures

### Initialization
The SDK initialization methods serves the dual purpose of sharing information about the SDK and performing any one time activities including initialization of internal variables and algorithms.

### Quality check
The quality check method is used to determine if the biometrics data is of sufficient quality for uniqueness check and authentication matches.

### Match
The matcher is used to perform checks if the provided input biometrics belong to the same person. The matcher has several use cases within mosip. It is used for 1:1 matches where a person's identity is verified using a biometrics match. It is also used for 1:n(few) matches for uniqueness checks.

URL: /match

Method: post

Content-Type: json

Body:

```json
{
  "sample": "BiometricRecord",
  "gallery": [
    "BiometricRecord 1",
    "BiometricRecord 2"
  ],
  "modalitiesToMatch": [
    "Finger",
    "Iris"
  ],
  "flags": {
    "xxx": "yyy"
  }
}
```

Response:

**Success**
```json
{
  "status": "true",
  "response": [
      {
        "galleryIndex": 0,
        "decisions": {
          "FINGER": {
            "match": "MATCHED",
            "errors": [],
            "analyticsInfo": {
              "analyticsx": "xxxxx"
            }
          },
          "IRIS": {
            "match": "MATCHED",
            "errors": [],
            "analyticsInfo": {
              "analyticsx": "xxxxx"
            }
          }
        },
        "analyticsInfo": {
          "analytics1": "xxxxx"
        }
      },
      {
        "galleryIndex": 1,
        "decisions": {
          "FINGER": {
            "match": "MATCHED",
            "errors": [],
            "analyticsInfo": {
              "analyticsx": "xxxxx"
            }
          },
          "IRIS": {
            "match": "MATCHED",
            "errors": [],
            "analyticsInfo": {
              "analyticsx": "xxxxx"
            }
          }
        },
        "analyticsInfo": {}
      }
    ],
  "errors": []
}
```

**Failure**
```json
{
  "status": "false",
  "response": "",
  "errors": [
    {
      "errorCode": "KER-ATH-401",
      "message": "Authentication Failed"
    }
  ]
}
```

### Extractor

URL: /extract

Method: post

Content-Type: json

Body:

```json
{
  "sample": "BiometricRecord",
  "modalitiesToMatch": [
    "Finger",
    "Iris"
  ],
  "flags": {
    "xxx": "yyy"
  }
}
```

Response:

**Success**
```json
{
  "status": "true",
  "response": "BiometricRecord <only the segments of the modalitiesToMatch>",
  "errors": []
}
```

**Failure**
```json
{
  "status": "false",
  "response": "",
  "errors": [
    {
      "errorCode": "KER-ATH-401",
      "message": "Authentication Failed"
    }
  ]
}
```

### Segmenter

### Converter

## Structures

### BiometricRecord

```json
{
  "version": {
    "major": 1,
    "minor": 1
  },
  "cbeffversion": {
    "major": 1,
    "minor": 1
  },
  "birInfo": {
    "creator": "mosip",
    "index": "1",
    "payload": "bW9zaXA=",
    "integrity": false,
    "creationDate": "2020-10-15T06:59:29.466Z",
    "notValidBefore": "2020-10-15T06:59:29.466Z",
    "notValidAfter": "2020-10-15T06:59:29.466Z"
  },
  "segments": [
    {
      "version": {
        "major": 1,
        "minor": 1
      },
      "cbeffversion": {
        "major": 1,
        "minor": 1
      },
      "birInfo": {
        "creator": "mosip",
        "index": "1",
        "payload": "bW9zaXA=",
        "integrity": false,
        "creationDate": "2020-10-15T06:59:29.466Z",
        "notValidBefore": "2020-10-15T06:59:29.466Z",
        "notValidAfter": "2020-10-15T06:59:29.466Z"
      },
      "bdbInfo": {
        "challengeResponse": null,
        "index": "xxxx",
        "encryption": null,
        "creationDate": "2020-10-15T06:59:29.466Z",
        "notValidBefore": "2020-10-15T06:59:29.466Z",
        "notValidAfter": "2020-10-15T06:59:29.466Z",
        "type": [
          "Finger"
        ],
        "subtype": [
          "Left IndexFinger"
        ],
        "level": "RAW",
        "product": null,
        "purpose": "ENROLL",
        "quality": {
          "algorithm": {
            "organization": "mosip",
            "type": "SHA-256"
          },
          "score": 12,
          "qualityCalculationFailed": null
        },
        "format": {
          "organization": "mosip",
          "type": "7"
        },
        "captureDevice": null,
        "featureExtractionAlgorithm": null,
        "comparisonAlgorithm": null,
        "compressionAlgorithm": null
      },
      "bdb": "bW9zaXAuaW8=",
      "sb": "bW9zaXA=",
      "sbInfo": {
        "format": {
          "organization": "mosip",
          "type": "sbbb"
        }
      },
      "others": {
        "other": "xx"
      }
    }
  ]
}
```