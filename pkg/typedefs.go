package undonut

import (
	"fmt"
	"io"
)

// ExitOption maps to DONUT_OPT_EXIT_*
type ExitOption int32

const (
	ExitOptionThread  ExitOption = 1
	ExitOptionProcess ExitOption = 2
)

func (e ExitOption) String() string {
	switch e {
	case ExitOptionThread:
		return "EXIT_OPTION_THREAD"
	case ExitOptionProcess:
		return "EXIT_OPTION_PROCESS"
	default:
		return "EXIT_OPTION_UNKNOWN"
	}
}

// Entropy maps to DONUT_ENTROPY_*
type Entropy int32

const (
	EntropyNone    Entropy = 1
	EntropyRandom  Entropy = 2
	EntropyDefault Entropy = 3
)

func (e Entropy) String() string {
	switch e {
	case EntropyNone:
		return "ENTROPY_NONE"
	case EntropyRandom:
		return "ENTROPY_RANDOM"
	case EntropyDefault:
		return "ENTROPY_DEFAULT"
	default:
		return "ENTROPY_UNKNOWN"
	}
}

// InstanceType maps to DONUT_INSTANCE_*
type InstanceType int32

const (
	InstanceTypeEmbed InstanceType = 1
	InstanceTypeHTTP  InstanceType = 2
	InstanceTypeDNS   InstanceType = 3
)

func (e InstanceType) String() string {
	switch e {
	case InstanceTypeEmbed:
		return "INSTANCE_EMBED"
	case InstanceTypeHTTP:
		return "INSTANCE_HTTP"
	case InstanceTypeDNS:
		return "INSTANCE_DNS"
	default:
		return "INSTANCE_UNKNOWN"
	}
}

// Bypass maps to DONUT_BYPASS_*
type Bypass int32

const (
	BypassNone     Bypass = 1
	BypassAbort    Bypass = 2
	BypassContinue Bypass = 3
)

func (e Bypass) String() string {
	switch e {
	case BypassNone:
		return "BYPASS_NONE"
	case BypassAbort:
		return "BYPASS_ABORT"
	case BypassContinue:
		return "BYPASS_CONTINUE"
	default:
		return "BYPASS_UNKNOWN"
	}
}

// ModuleType maps to DONUT_MODULE_*
type ModuleType int32

const (
	ModuleTypeNETDLL ModuleType = 1
	ModuleTypeNETEXE ModuleType = 2
	ModuleTypeDLL    ModuleType = 3
	ModuleTypeEXE    ModuleType = 4
	ModuleTypeVBS    ModuleType = 5
	ModuleTypeJS     ModuleType = 6
)

func (e ModuleType) String() string {
	switch e {
	case ModuleTypeNETDLL:
		return "MODULE_NET_DLL"
	case ModuleTypeNETEXE:
		return "MODULE_NET_EXE"
	case ModuleTypeDLL:
		return "MODULE_DLL"
	case ModuleTypeEXE:
		return "MODULE_EXE"
	case ModuleTypeVBS:
		return "MODULE_VBS"
	case ModuleTypeJS:
		return "MODULE_JS"
	default:
		return "MODULE_UNKNOWN"
	}
}

// Compress maps to DONUT_COMPRESS_*
type Compress int32

const (
	CompressNone       Compress = 1
	CompressAPLIB      Compress = 2
	CompressLZNT1      Compress = 3
	CompressXPRESS     Compress = 4
	CompressXPRESSHUFF Compress = 5
)

func (e Compress) String() string {
	switch e {
	case CompressNone:
		return "COMPRESS_NONE"
	case CompressAPLIB:
		return "COMPRESS_APLIB"
	case CompressLZNT1:
		return "COMPRESS_LZNT1"
	case CompressXPRESS:
		return "COMPRESS_XPRESS"
	case CompressXPRESSHUFF:
		return "COMPRESS_XPRESS_HUFF"
	default:
		return "COMPRESS_UNKNOWN"
	}
}

type (
	Crypt struct {
		MasterKey [16]byte
		Nonce     [16]byte
	}

	GUID struct {
		Data1 uint32
		Data2 uint16
		Data3 uint16
		Data4 [8]byte
	}

	instanceHeader struct {
		Size               uint32
		Crypt              Crypt
		IV                 uint64
		API                [516]byte
		ExitOpt            ExitOption
		Entropy            Entropy
		OriginalEntrypoint uint64
		//EncryptedInstance  []byte
	}

	instanceBody struct {
		APICnt   int32
		DLLNames [256]byte

		Dataname   [8]byte
		KernelBase [12]byte
		AMSI       [8]byte
		CLR        [4]byte
		WLDP       [8]byte
		CMDSyms    [256]byte

		ExitAPI [256]byte

		Bypass         Bypass
		WLDPQuery      [32]byte
		WLDPIsApproved [32]byte
		AMSIInitialize [16]byte
		AMSIScanBuffer [16]byte
		AMSIScanString [16]byte

		WScript    [8]byte
		WScriptEXE [12]byte

		IUnknown  GUID
		IDispatch GUID

		// dotnet magic
		CLSIDCLRMetaHost    GUID
		CLRMetaHost         GUID
		CLRRuntimeInfo      GUID
		CLSIDCorRuntimeHost GUID
		CorRuntimeHost      GUID
		AppDomain           GUID

		// vbs and js magic
		CLSIDScriptLanguage     GUID
		IHost                   GUID
		IActiveScript           GUID
		IActiveScriptSite       GUID
		IActiveScriptSiteWindow GUID
		IActiveScriptParse32    GUID
		IActiveScriptParse64    GUID

		TypeV   InstanceType
		Server  [256]byte
		HTTPReq [8]byte

		Sig [256]byte
		MAC uint64

		Crypt
		ModuleLen uint64
		Module    Module
	}

	Module struct {
		TypeV    ModuleType
		Thread   int32
		Compress Compress

		Runtime [256]byte
		Domain  [256]byte
		CLS     [256]byte
		Method  [256]byte

		Param   [256]byte
		Unicode int32

		Sig [8]byte
		MAC uint64

		CompressedSize uint32
		Size           uint32
	}
)

type Instance struct {
	instanceHeader
	instanceBody
	Data io.Reader
}

func (s *Instance) String() string {
	return fmt.Sprintf(
		`Donut Instance:
 [*] Size: %v
 [*] Instance Master Key: %v
 [*] Instance Nonce: %v
 [*] IV: %x
 [*] Exit Option: %s
 [*] Entropy: %s
 [*] DLLs: %s
 [*] AMSI Bypass: %s
 [*] Instance Type: %s
 [*] Module Master Key: %v
 [*] Module Nonce: %v
 [*] Module Type: %s
 [*] Module Compression: %s
`,
		s.Size,
		s.instanceHeader.Crypt.MasterKey,
		s.instanceHeader.Crypt.Nonce,
		s.IV,
		s.ExitOpt,
		s.Entropy,
		s.DLLNames,
		s.Bypass,
		s.TypeV,
		s.instanceBody.Crypt.MasterKey,
		s.instanceBody.Crypt.Nonce,
		s.Module.TypeV,
		s.Module.Compress,
	)
}
