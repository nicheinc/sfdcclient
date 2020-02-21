package sfdcclient

import (
	"testing"
)

func TestOAuthErr_Error(t *testing.T) {
	type fields struct {
		Code        string
		Description string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Success",
			fields: fields{
				Code:        "invalid_grant",
				Description: "Session expired or invalid",
			},
			want: "error code: invalid_grant, description: Session expired or invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &OAuthErr{
				Code:        tt.fields.Code,
				Description: tt.fields.Description,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("OAuthErr.Error() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestErrorObject_Error(t *testing.T) {
	type fields struct {
		Message string
		ErrCode string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Success",
			fields: fields{
				Message: "Session expired or invalid",
				ErrCode: "INVALID_SESSION_ID",
			},
			want: "error code: INVALID_SESSION_ID, message: Session expired or invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ErrorObject{
				Message: tt.fields.Message,
				ErrCode: tt.fields.ErrCode,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ErrorObject.Error() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestErrorObjects_Error(t *testing.T) {
	tests := []struct {
		name string
		e    *ErrorObjects
		want string
	}{
		{
			name: "NilErrs",
			e:    nil,
			want: "",
		},
		{
			name: "EmptyErrsSlice",
			e:    &ErrorObjects{},
			want: "",
		},
		{
			name: "OneErr",
			e: &ErrorObjects{
				ErrorObject{
					ErrCode: "123",
					Message: "message",
					Fields:  []string{"field"},
				},
			},
			want: "error code: 123, message: message, fields: field",
		},
		{
			name: "MultipleErrs",
			e: &ErrorObjects{
				ErrorObject{
					ErrCode: "123",
					Message: "message",
					Fields:  []string{"field"},
				},
				ErrorObject{
					ErrCode: "456",
					Message: "otherMessage",
					Fields:  []string{"otherField"},
				},
			},
			want: "error code: 123, message: message, fields: field\nerror code: 456, message: otherMessage, fields: otherField",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("ErrorObjects.Error() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
