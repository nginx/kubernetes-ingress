package appprotect

import (
	"io"
	"log/slog"
	"testing"
	"time"

	nl "github.com/nginx/kubernetes-ingress/internal/logger"
	nic_glog "github.com/nginx/kubernetes-ingress/internal/logger/glog"
	"github.com/nginx/kubernetes-ingress/internal/logger/levels"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func parseTime(value string) *time.Time {
	t, err := time.Parse(timeLayout, value)
	if err != nil {
		panic(err)
	}

	return &t
}

func sliceCmpFunc(x, y *unstructured.Unstructured) bool {
	return x.GetUID() > y.GetUID()
}

var unstructuredSliceCmpOpts = cmpopts.SortSlices(sliceCmpFunc)

func TestCreateAppProtectPolicyEx(t *testing.T) {
	t.Parallel()
	tests := []struct {
		policy           *unstructured.Unstructured
		expectedPolicyEx *PolicyEx
		wantErr          bool
		msg              string
	}{
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"uid": "1",
					},
					"spec": map[string]interface{}{
						"policy": map[string]interface{}{
							"name": "TestPolicy",
							"signature-requirements": []interface{}{
								map[string]interface{}{
									"maxRevisionDatetime": "2020-01-23T18:32:02Z",
									"minRevisionDatetime": "2020-01-21T18:32:02Z",
									"tag":                 "MinMax",
								},
								map[string]interface{}{
									"maxRevisionDatetime": "2020-01-23T18:32:02Z",
									"tag":                 "Max",
								},
								map[string]interface{}{
									"minRevisionDatetime": "2020-01-23T18:32:02Z",
									"tag":                 "Min",
								},
							},
						},
					},
				},
			},
			expectedPolicyEx: &PolicyEx{
				SignatureReqs: []SignatureReq{
					{
						Tag: "MinMax",
						RevTimes: &RevTimes{
							MinRevTime: parseTime("2020-01-21T18:32:02Z"),
							MaxRevTime: parseTime("2020-01-23T18:32:02Z"),
						},
					},
					{
						Tag: "Max",
						RevTimes: &RevTimes{
							MaxRevTime: parseTime("2020-01-23T18:32:02Z"),
						},
					},
					{
						Tag: "Min",
						RevTimes: &RevTimes{
							MinRevTime: parseTime("2020-01-23T18:32:02Z"),
						},
					},
				},
				IsValid:  true,
				ErrorMsg: "",
			},
			wantErr: false,
			msg:     "valid policy",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"policy": map[string]interface{}{
							"name": "TestPolicy",
							"signature-requirements": []interface{}{
								map[string]interface{}{
									"minRevisionDatetime": "time",
									"tag":                 "MinMax",
								},
							},
						},
					},
				},
			},
			expectedPolicyEx: &PolicyEx{
				SignatureReqs: nil,
				IsValid:       false,
				ErrorMsg:      "invalid timestamp",
			},
			wantErr: true,
			msg:     "policy with invalid min timestamp",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"policy": map[string]interface{}{
							"name": "TestPolicy",
							"signature-requirements": []interface{}{
								map[string]interface{}{
									"maxRevisionDatetime": "time",
									"tag":                 "MinMax",
								},
							},
						},
					},
				},
			},
			expectedPolicyEx: &PolicyEx{
				SignatureReqs: nil,
				IsValid:       false,
				ErrorMsg:      "invalid timestamp",
			},
			wantErr: true,
			msg:     "policy with invalid max timestamp",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			expectedPolicyEx: &PolicyEx{
				SignatureReqs: nil,
				IsValid:       false,
				ErrorMsg:      "validation failed",
			},
			wantErr: true,
			msg:     "policy empty spec",
		},
		{
			policy: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"policy": map[string]interface{}{
							"name": "TestPolicy",
							"signature-requirements": map[string]interface{}{
								"invalid": map[string]interface{}{
									"maxRevisionDatetime": "time",
									"tag":                 "MinMax",
								},
							},
						},
					},
				},
			},
			expectedPolicyEx: &PolicyEx{
				SignatureReqs: nil,
				IsValid:       false,
				ErrorMsg:      failedValidationErrorMsg,
			},
			wantErr: true,
			msg:     "policy with incorrect structure",
		},
	}

	for _, test := range tests {
		test.expectedPolicyEx.Obj = test.policy
		l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
		policyEx, err := createAppProtectPolicyEx(test.policy, l)
		if (err != nil) != test.wantErr {
			t.Errorf("createAppProtectPolicyEx() returned %v, for the case of %s", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedPolicyEx, policyEx); diff != "" {
			t.Errorf("createAppProtectPolicyEx() %q returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestCreateAppProtectLogConfEx(t *testing.T) {
	t.Parallel()
	tests := []struct {
		logConf           *unstructured.Unstructured
		expectedLogConfEx *LogConfEx
		wantErr           bool
		msg               string
	}{
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"content": map[string]interface{}{},
						"filter":  map[string]interface{}{},
					},
				},
			},
			expectedLogConfEx: &LogConfEx{
				IsValid:  true,
				ErrorMsg: "",
			},
			wantErr: false,
			msg:     "Valid LogConf",
		},
		{
			logConf: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"content": map[string]interface{}{},
					},
				},
			},
			expectedLogConfEx: &LogConfEx{
				IsValid:  false,
				ErrorMsg: failedValidationErrorMsg,
			},
			wantErr: true,
			msg:     "Invalid LogConf",
		},
	}

	for _, test := range tests {
		test.expectedLogConfEx.Obj = test.logConf

		policyEx, err := createAppProtectLogConfEx(test.logConf)
		if (err != nil) != test.wantErr {
			t.Errorf("createAppProtectLogConfEx() returned %v, for the case of %s", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedLogConfEx, policyEx); diff != "" {
			t.Errorf("createAppProtectLogConfEx() %q returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestCreateAppProtectUserSigEx(t *testing.T) {
	t.Parallel()
	tests := []struct {
		userSig           *unstructured.Unstructured
		expectedUserSigEx *UserSigEx
		wantErr           bool
		msg               string
	}{
		{
			userSig: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"revisionDatetime": "2020-01-23T18:32:02Z",
						"signatures": []interface{}{
							map[string]interface{}{},
						},
						"tag": "test",
					},
				},
			},
			expectedUserSigEx: &UserSigEx{
				RevTime:  parseTime("2020-01-23T18:32:02Z"),
				IsValid:  true,
				ErrorMsg: "",
				Tag:      "test",
			},
			wantErr: false,
			msg:     "Valid UserSig",
		},
		{
			userSig: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"signatures": []interface{}{
							map[string]interface{}{},
						},
						"tag": "test",
					},
				},
			},
			expectedUserSigEx: &UserSigEx{
				IsValid:  true,
				ErrorMsg: "",
				Tag:      "test",
			},
			wantErr: false,
			msg:     "Valid UserSig, no revDateTime",
		},
		{
			userSig: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"revisionDatetime": "time",
						"signatures": []interface{}{
							map[string]interface{}{},
						},
						"tag": "test",
					},
				},
			},
			expectedUserSigEx: &UserSigEx{
				IsValid:  false,
				ErrorMsg: invalidTimestampErrorMsg,
				Tag:      "",
			},
			wantErr: true,
			msg:     "Invalid timestamp",
		},
	}

	for _, test := range tests {
		test.expectedUserSigEx.Obj = test.userSig

		userSigEx, err := createAppProtectUserSigEx(test.userSig)
		if (err != nil) != test.wantErr {
			t.Errorf("createAppProtectUserSigEx() returned %v, for the case of %s", err, test.msg)
		}
		if diff := cmp.Diff(test.expectedUserSigEx, userSigEx); diff != "" {
			t.Errorf("createAppProtectUserSigEx() %q returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestIsReqSatisfiedByUserSig(t *testing.T) {
	t.Parallel()
	userSigEx := &UserSigEx{Tag: "test", RevTime: parseTime("2020-06-16T18:32:01Z")}
	userSigExNoRevTime := &UserSigEx{Tag: "test"}
	tests := []struct {
		sigReq   SignatureReq
		sigEx    *UserSigEx
		msg      string
		expected bool
	}{
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2020-01-21T18:32:02Z"),
					MaxRevTime: parseTime("2020-10-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Valid, Basic case",
			expected: true,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2021-01-21T18:32:02Z"),
					MaxRevTime: parseTime("2022-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Invalid, rev not in Required period",
			expected: false,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MaxRevTime: parseTime("2022-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Valid, max rev time only",
			expected: true,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MaxRevTime: parseTime("2019-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Invalid, max rev time only",
			expected: false,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2019-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Valid, min rev time only",
			expected: true,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2022-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Invalid, min rev time only",
			expected: false,
		},
		{
			sigReq: SignatureReq{
				Tag: "testing",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2022-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigEx,
			msg:      "Invalid, different tag",
			expected: false,
		},
		{
			sigReq: SignatureReq{
				Tag:      "testing",
				RevTimes: &RevTimes{},
			},
			sigEx:    userSigEx,
			msg:      "Invalid, different tag, no revTimes",
			expected: false,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
			},
			sigEx:    userSigEx,
			msg:      "Valid, matching tag, no revTimes",
			expected: true,
		},
		{
			sigReq: SignatureReq{
				Tag: "test",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2019-01-23T18:32:02Z"),
				},
			},
			sigEx:    userSigExNoRevTime,
			msg:      "Valid, no RevDateTime",
			expected: true,
		},
	}

	for _, test := range tests {
		result := isReqSatisfiedByUserSig(test.sigReq, test.sigEx)
		if result != test.expected {
			t.Errorf("Unexpected result in test case %s: got %v, expected: %v", test.msg, result, test.expected)
		}
	}
}

func TestAddOrUpdatePolicy(t *testing.T) {
	t.Parallel()
	basicTestPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
			},
			"spec": map[string]interface{}{
				"policy": map[string]interface{}{
					"name": "TestPolicy",
					"signature-requirements": []interface{}{
						map[string]interface{}{
							"maxRevisionDatetime": "2019-04-01T18:32:02Z",
							"tag":                 "test",
						},
					},
				},
			},
		},
	}
	basicTestPolicyNoReqs := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
			},
			"spec": map[string]interface{}{
				"policy": map[string]interface{}{
					"name": "TestPolicy",
				},
			},
		},
	}
	invalidTestPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
			},
			"spec": map[string]interface{}{},
		},
	}
	testPolicyUnsatisfied := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
			},
			"spec": map[string]interface{}{
				"policy": map[string]interface{}{
					"name": "TestPolicy",
					"signature-requirements": []interface{}{
						map[string]interface{}{
							"minRevisionDatetime": "2021-04-01T18:32:02Z",
							"tag":                 "test",
						},
					},
				},
			},
		},
	}
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	apc := newConfigurationImpl(l)
	apc.UserSigs["testing/TestUsersig"] = &UserSigEx{Tag: "test", RevTime: parseTime("2019-01-01T18:32:02Z"), IsValid: true}
	tests := []struct {
		policy           *unstructured.Unstructured
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			policy: basicTestPolicy,
			expectedChanges: []Change{
				{
					Resource: &PolicyEx{
						Obj:     basicTestPolicy,
						IsValid: true,
						SignatureReqs: []SignatureReq{
							{
								Tag: "test",
								RevTimes: &RevTimes{
									MaxRevTime: parseTime("2019-04-01T18:32:02Z"),
								},
							},
						},
					},
					Op: AddOrUpdate,
				},
			},
			expectedProblems: nil,
			msg:              "Basic Case with sig reqs",
		},
		{
			policy: basicTestPolicyNoReqs,
			expectedChanges: []Change{
				{
					Resource: &PolicyEx{
						Obj:           basicTestPolicyNoReqs,
						IsValid:       true,
						SignatureReqs: []SignatureReq{},
					},
					Op: AddOrUpdate,
				},
			},
			expectedProblems: nil,
			msg:              "basic case no sig reqs",
		},
		{
			policy: invalidTestPolicy,
			expectedChanges: []Change{
				{
					Resource: &PolicyEx{
						Obj:      invalidTestPolicy,
						IsValid:  false,
						ErrorMsg: "validation failed",
					},
					Op: Delete,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  invalidTestPolicy,
					Reason:  nl.EventReasonRejected,
					Message: "Error validating policy : error validating App Protect Policy : required field map[] not found",
				},
			},
			msg: "validation failed",
		},
		{
			policy: testPolicyUnsatisfied,
			expectedChanges: []Change{
				{
					Resource: &PolicyEx{
						Obj:      testPolicyUnsatisfied,
						IsValid:  false,
						ErrorMsg: "policy has unsatisfied signature requirements",
						SignatureReqs: []SignatureReq{
							{
								Tag: "test",
								RevTimes: &RevTimes{
									MinRevTime: parseTime("2021-04-01T18:32:02Z"),
								},
							},
						},
					},
					Op: Delete,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  testPolicyUnsatisfied,
					Reason:  nl.EventReasonRejected,
					Message: "policy has unsatisfied signature requirements",
				},
			},
			msg: "Missing sig reqs",
		},
	}
	for _, test := range tests {
		aPChans, aPProbs := apc.AddOrUpdatePolicy(test.policy)
		if diff := cmp.Diff(test.expectedChanges, aPChans); diff != "" {
			t.Errorf("AddOrUpdatePolicy() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, aPProbs); diff != "" {
			t.Errorf("AddOrUpdatePolicy() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddOrUpdateLogConf(t *testing.T) {
	t.Parallel()
	validLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
				"name":      "testlogconf",
			},
			"spec": map[string]interface{}{
				"content": map[string]interface{}{},
				"filter":  map[string]interface{}{},
			},
		},
	}
	invalidLogConf := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": "testing",
				"name":      "testlogconf",
			},
			"spec": map[string]interface{}{
				"content": map[string]interface{}{},
			},
		},
	}
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	apc := NewConfiguration(l)
	tests := []struct {
		logconf          *unstructured.Unstructured
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			logconf: validLogConf,
			expectedChanges: []Change{
				{
					Resource: &LogConfEx{
						Obj:     validLogConf,
						IsValid: true,
					},
					Op: AddOrUpdate,
				},
			},
			expectedProblems: nil,
			msg:              "Basic Case",
		},
		{
			logconf: invalidLogConf,
			expectedChanges: []Change{
				{
					Resource: &LogConfEx{
						Obj:      invalidLogConf,
						IsValid:  false,
						ErrorMsg: "validation failed",
					},
					Op: Delete,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  invalidLogConf,
					Reason:  nl.EventReasonRejected,
					Message: "error validating App Protect Log Configuration testlogconf: required field map[] not found",
				},
			},
			msg: "validation failed",
		},
	}
	for _, test := range tests {
		aPChans, aPProbs := apc.AddOrUpdateLogConf(test.logconf)
		if diff := cmp.Diff(test.expectedChanges, aPChans); diff != "" {
			t.Errorf("AddOrUpdateLogConf() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, aPProbs); diff != "" {
			t.Errorf("AddOrUpdateLogConf() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestAddOrUpdateUserSig(t *testing.T) {
	t.Parallel()
	testUserSig1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test1",
				"uid":               "1",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"signatures": []interface{}{
					map[string]interface{}{},
				},
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test1",
			},
		},
	}
	testUserSig2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test2",
				"uid":               "2",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"signatures": []interface{}{
					map[string]interface{}{},
				},
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test2",
			},
		},
	}
	invalidTestUserSig2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test2",
				"uid":               "3",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test2",
			},
		},
	}
	testUserSigDupTag := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test2",
				"uid":               "4",
				"creationTimestamp": "2020-01-25T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"signatures": []interface{}{
					map[string]interface{}{},
				},
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test1",
			},
		},
	}
	testUserSig1Invalid := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test1",
				"uid":               "1",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
		},
	}
	testUserSig3 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test3",
				"uid":               "5",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"signatures": []interface{}{
					map[string]interface{}{},
				},
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test3",
			},
		},
	}

	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	appProtectConfiguration := newConfigurationImpl(l)
	appProtectConfiguration.UserSigs["testing/test1"] = &UserSigEx{
		Obj:      testUserSig1,
		Tag:      "test1",
		IsValid:  true,
		ErrorMsg: "",
	}
	appProtectConfiguration.Policies["testing/testpolicy"] = &PolicyEx{
		Obj:      &unstructured.Unstructured{Object: map[string]interface{}{}},
		IsValid:  false,
		ErrorMsg: "policy has unsatisfied signature requirements",
		SignatureReqs: []SignatureReq{
			{
				Tag: "test3",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2010-01-23T18:32:02Z"),
				},
			},
		},
	}
	tests := []struct {
		usersig               *unstructured.Unstructured
		expectedUserSigChange UserSigChange
		expectedProblems      []Problem
		msg                   string
	}{
		{
			usersig: testUserSig2,
			expectedUserSigChange: UserSigChange{
				UserSigs: []*unstructured.Unstructured{
					testUserSig1,
					testUserSig2,
				},
			},
			msg: "Basic case",
		},
		{
			usersig: invalidTestUserSig2,
			expectedUserSigChange: UserSigChange{
				UserSigs: []*unstructured.Unstructured{
					testUserSig1,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  invalidTestUserSig2,
					Reason:  nl.EventReasonRejected,
					Message: "validation failed",
				},
			},
			msg: "validation failed",
		},
		{
			usersig: testUserSigDupTag,
			expectedUserSigChange: UserSigChange{
				UserSigs: []*unstructured.Unstructured{
					testUserSig1,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  testUserSigDupTag,
					Message: "duplicate tag set",
					Reason:  nl.EventReasonRejected,
				},
			},
			msg: "Duplicate tags",
		},
		{
			usersig: testUserSig1Invalid,
			expectedUserSigChange: UserSigChange{
				UserSigs: []*unstructured.Unstructured{
					testUserSigDupTag,
				},
			},
			expectedProblems: []Problem{
				{
					Object:  testUserSig1Invalid,
					Message: "validation failed",
					Reason:  nl.EventReasonRejected,
				},
			},
			msg: "UserSig becomes valid after previous tag holder became invalid",
		},
		{
			usersig: testUserSig3,
			expectedUserSigChange: UserSigChange{
				PolicyAddsOrUpdates: []*unstructured.Unstructured{
					{
						Object: map[string]interface{}{},
					},
				},
				UserSigs: []*unstructured.Unstructured{
					testUserSigDupTag,
					testUserSig3,
				},
			},
			msg: "Policy becomes valid after a UserSig with the right tag was added",
		},
	}

	for _, test := range tests {
		apUserSigChan, apProbs := appProtectConfiguration.AddOrUpdateUserSig(test.usersig)
		if diff := cmp.Diff(test.expectedUserSigChange, apUserSigChan, unstructuredSliceCmpOpts); diff != "" {
			t.Errorf("AddOrUpdateUserSig() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, apProbs); diff != "" {
			t.Errorf("AddOrUpdateUserSig() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestDeletePolicy(t *testing.T) {
	t.Parallel()
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	appProtectConfiguration := newConfigurationImpl(l)
	appProtectConfiguration.Policies["testing/test"] = &PolicyEx{}
	tests := []struct {
		key              string
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			key: "testing/test",
			expectedChanges: []Change{
				{
					Op:       Delete,
					Resource: &PolicyEx{},
				},
			},
			expectedProblems: nil,
			msg:              "Positive",
		},
		{
			key:              "testing/notpresent",
			expectedChanges:  nil,
			expectedProblems: nil,
			msg:              "Negative",
		},
	}
	for _, test := range tests {
		apChan, apProbs := appProtectConfiguration.DeletePolicy(test.key)
		if diff := cmp.Diff(test.expectedChanges, apChan); diff != "" {
			t.Errorf("DeletePolicy() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, apProbs); diff != "" {
			t.Errorf("DeletePolicy() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestDeleteLogConf(t *testing.T) {
	t.Parallel()
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	appProtectConfiguration := newConfigurationImpl(l)
	appProtectConfiguration.LogConfs["testing/test"] = &LogConfEx{}
	tests := []struct {
		key              string
		expectedChanges  []Change
		expectedProblems []Problem
		msg              string
	}{
		{
			key: "testing/test",
			expectedChanges: []Change{
				{
					Op:       Delete,
					Resource: &LogConfEx{},
				},
			},
			expectedProblems: nil,
			msg:              "Positive",
		},
		{
			key:              "testing/notpresent",
			expectedChanges:  nil,
			expectedProblems: nil,
			msg:              "Negative",
		},
	}
	for _, test := range tests {
		apChan, apProbs := appProtectConfiguration.DeleteLogConf(test.key)
		if diff := cmp.Diff(test.expectedChanges, apChan); diff != "" {
			t.Errorf("DeleteLogConf() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, apProbs); diff != "" {
			t.Errorf("DeleteLogConf() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestDeleteUserSig(t *testing.T) {
	t.Parallel()
	testUserSig1 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test1",
				"uid":               "1",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"signatures": []interface{}{
					map[string]interface{}{},
				},
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test1",
			},
		},
	}
	testUserSig2 := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace":         "testing",
				"name":              "test2",
				"uid":               "2",
				"creationTimestamp": "2020-01-23T18:32:02Z",
			},
			"spec": map[string]interface{}{
				"signatures": []interface{}{
					map[string]interface{}{},
				},
				"revisionDatetime": "2020-01-23T18:32:02Z",
				"tag":              "test2",
			},
		},
	}
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	appProtectConfiguration := newConfigurationImpl(l)
	appProtectConfiguration.UserSigs["testing/test1"] = &UserSigEx{
		IsValid: true,
		Obj:     testUserSig1,
	}
	appProtectConfiguration.UserSigs["testing/test2"] = &UserSigEx{
		IsValid: true,
		Obj:     testUserSig2,
	}
	appProtectConfiguration.Policies["testing/testpolicy"] = &PolicyEx{
		Obj:      &unstructured.Unstructured{Object: map[string]interface{}{}},
		IsValid:  true,
		ErrorMsg: "",
		SignatureReqs: []SignatureReq{
			{
				Tag: "test1",
				RevTimes: &RevTimes{
					MinRevTime: parseTime("2010-01-23T18:32:02Z"),
				},
			},
		},
	}
	tests := []struct {
		key              string
		expectedChange   UserSigChange
		expectedProblems []Problem
		msg              string
	}{
		{
			key: "testing/test1",
			expectedChange: UserSigChange{
				PolicyDeletions: []*unstructured.Unstructured{
					{
						Object: map[string]interface{}{},
					},
				},
				UserSigs: []*unstructured.Unstructured{
					testUserSig2,
				},
			},
			expectedProblems: []Problem{
				{
					Reason:  nl.EventReasonRejected,
					Message: "policy has unsatisfied signature requirements",
					Object: &unstructured.Unstructured{
						Object: map[string]interface{}{},
					},
				},
			},
			msg: "Positive, policy gets set to invalid",
		},
		{
			key:              "testing/test3",
			expectedChange:   UserSigChange{},
			expectedProblems: nil,
			msg:              "Negative",
		},
	}

	for _, test := range tests {
		apChan, apProbs := appProtectConfiguration.DeleteUserSig(test.key)
		if diff := cmp.Diff(test.expectedChange, apChan, unstructuredSliceCmpOpts); diff != "" {
			t.Errorf("DeleteUserSig() %q changes returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
		if diff := cmp.Diff(test.expectedProblems, apProbs); diff != "" {
			t.Errorf("DeleteUserSig() %q problems returned unexpected result (-want +got):\n%s", test.msg, diff)
		}
	}
}

func TestGetAppProtectResource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kind    string
		key     string
		wantErr bool
		errMsg  string
		msg     string
	}{
		{
			kind:    "APPolicy",
			key:     "testing/test1",
			wantErr: false,
			msg:     "Policy, positive",
		},
		{
			kind:    "APPolicy",
			key:     "testing/test2",
			wantErr: true,
			errMsg:  "validation failed",
			msg:     "Policy, Negative, invalid object",
		},
		{
			kind:    "APPolicy",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "app protect Policy testing/test3 not found",
			msg:     "Policy, Negative, Object Does not exist",
		},
		{
			kind:    "APLogConf",
			key:     "testing/test1",
			wantErr: false,
			msg:     "LogConf, positive",
		},
		{
			kind:    "APLogConf",
			key:     "testing/test2",
			wantErr: true,
			errMsg:  "validation failed",
			msg:     "LogConf, Negative, invalid object",
		},
		{
			kind:    "APLogConf",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "app protect LogConf testing/test3 not found",
			msg:     "LogConf, Negative, Object Does not exist",
		},
		{
			kind:    "APUserSig",
			key:     "testing/test1",
			wantErr: false,
			msg:     "UserSig, positive",
		},
		{
			kind:    "APUserSig",
			key:     "testing/test2",
			wantErr: true,
			errMsg:  "validation failed",
			msg:     "UserSig, Negative, invalid object",
		},
		{
			kind:    "APUserSig",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "app protect UserSig testing/test3 not found",
			msg:     "UserSig, Negative, Object Does not exist",
		},
		{
			kind:    "Notreal",
			key:     "testing/test3",
			wantErr: true,
			errMsg:  "unknown app protect resource kind Notreal",
			msg:     "Invalid kind, Negative",
		},
	}
	l := slog.New(nic_glog.New(io.Discard, &nic_glog.Options{Level: levels.LevelInfo}))
	appProtectConfiguration := newConfigurationImpl(l)
	appProtectConfiguration.Policies["testing/test1"] = &PolicyEx{IsValid: true, Obj: &unstructured.Unstructured{}}
	appProtectConfiguration.Policies["testing/test2"] = &PolicyEx{IsValid: false, Obj: &unstructured.Unstructured{}, ErrorMsg: "validation failed"}
	appProtectConfiguration.LogConfs["testing/test1"] = &LogConfEx{IsValid: true, Obj: &unstructured.Unstructured{}}
	appProtectConfiguration.LogConfs["testing/test2"] = &LogConfEx{IsValid: false, Obj: &unstructured.Unstructured{}, ErrorMsg: "validation failed"}
	appProtectConfiguration.UserSigs["testing/test1"] = &UserSigEx{IsValid: true, Obj: &unstructured.Unstructured{}}
	appProtectConfiguration.UserSigs["testing/test2"] = &UserSigEx{IsValid: false, Obj: &unstructured.Unstructured{}, ErrorMsg: "validation failed"}

	for _, test := range tests {
		_, err := appProtectConfiguration.GetAppResource(test.kind, test.key)
		if (err != nil) != test.wantErr {
			t.Errorf("GetAppResource() returned %v on case %s", err, test.msg)
		}
		if test.wantErr || err != nil {
			if test.errMsg != err.Error() {
				t.Errorf("GetAppResource() returned error message %s on case %s (expected %s)", err.Error(), test.msg, test.errMsg)
			}
		}
	}
}
