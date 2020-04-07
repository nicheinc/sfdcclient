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
			want: "OAuth authorization error code: invalid_grant, description: Session expired or invalid",
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

func TestAPIErr_Error(t *testing.T) {
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
			e := &APIErr{
				Message: tt.fields.Message,
				ErrCode: tt.fields.ErrCode,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("APIErr.Error() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestAPIErrs_Error(t *testing.T) {
	tests := []struct {
		name string
		e    *APIErrs
		want string
	}{
		{
			name: "NilErrs",
			e:    nil,
			want: "",
		},
		{
			name: "EmptyErrsSlice",
			e:    &APIErrs{},
			want: "",
		},
		{
			name: "OneErr",
			e: &APIErrs{
				APIErr{
					ErrCode: "123",
					Message: "message",
					Fields:  []string{"field"},
				},
			},
			want: "error code: 123, message: message, fields: field",
		},
		{
			name: "MultipleErrs",
			e: &APIErrs{
				APIErr{
					ErrCode: "123",
					Message: "message",
					Fields:  []string{"field"},
				},
				APIErr{
					ErrCode: "456",
					Message: "otherMessage",
					Fields:  []string{"otherField"},
				},
			},
			want: "error code: 123, message: message, fields: field|error code: 456, message: otherMessage, fields: otherField",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.Error(); got != tt.want {
				t.Errorf("APIErrs.Error() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
