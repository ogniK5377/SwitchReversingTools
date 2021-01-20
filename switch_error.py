import switch_utils as su
import sys

ERROR_MODULES = {
	0: 'ErrorModule::Common',
	1: 'ErrorModule::Kernel',
	2: 'ErrorModule::FS',
	3: 'ErrorModule::OS',
	4: 'ErrorModule::HTCS',
	5: 'ErrorModule::NCM',
	6: 'ErrorModule::DD',
	8: 'ErrorModule::LR',
	9: 'ErrorModule::Loader',
	10: 'ErrorModule::CMIF',
	11: 'ErrorModule::HIPC',
	15: 'ErrorModule::PM',
	16: 'ErrorModule::NS',
	18: 'ErrorModule::HTC',
	20: 'ErrorModule::NCMContent',
	21: 'ErrorModule::SM',
	22: 'ErrorModule::RO',
	24: 'ErrorModule::SDMMC',
	25: 'ErrorModule::OVLN',
	26: 'ErrorModule::SPL',
	100: 'ErrorModule::ETHC',
	101: 'ErrorModule::I2C',
	102: 'ErrorModule::GPIO',
	103: 'ErrorModule::UART',
	105: 'ErrorModule::Settings',
	107: 'ErrorModule::WLAN',
	108: 'ErrorModule::XCD',
	110: 'ErrorModule::NIFM',
	111: 'ErrorModule::Hwopus',
	113: 'ErrorModule::Bluetooth',
	114: 'ErrorModule::VI',
	115: 'ErrorModule::NFP',
	116: 'ErrorModule::Time',
	117: 'ErrorModule::FGM',
	118: 'ErrorModule::OE',
	120: 'ErrorModule::PCIe',
	121: 'ErrorModule::Friends',
	122: 'ErrorModule::BCAT',
	123: 'ErrorModule::SSL',
	124: 'ErrorModule::Account',
	125: 'ErrorModule::News',
	126: 'ErrorModule::Mii',
	127: 'ErrorModule::NFC',
	128: 'ErrorModule::AM',
	129: 'ErrorModule::PlayReport',
	130: 'ErrorModule::AHID',
	132: 'ErrorModule::Qlaunch',
	133: 'ErrorModule::PCV',
	134: 'ErrorModule::OMM',
	135: 'ErrorModule::BPC',
	136: 'ErrorModule::PSM',
	137: 'ErrorModule::NIM',
	138: 'ErrorModule::PSC',
	139: 'ErrorModule::TC',
	140: 'ErrorModule::USB',
	141: 'ErrorModule::NSD',
	142: 'ErrorModule::PCTL',
	143: 'ErrorModule::BTM',
	145: 'ErrorModule::ETicket',
	146: 'ErrorModule::NGC',
	147: 'ErrorModule::ERPT',
	148: 'ErrorModule::APM',
	150: 'ErrorModule::Profiler',
	151: 'ErrorModule::ErrorUpload',
	153: 'ErrorModule::Audio',
	154: 'ErrorModule::NPNS',
	155: 'ErrorModule::NPNSHTTPSTREAM',
	157: 'ErrorModule::ARP',
	158: 'ErrorModule::SWKBD',
	159: 'ErrorModule::BOOT',
	161: 'ErrorModule::NFCMifare',
	162: 'ErrorModule::UserlandAssert',
	163: 'ErrorModule::Fatal',
	164: 'ErrorModule::NIMShop',
	165: 'ErrorModule::SPSM',
	167: 'ErrorModule::BGTC',
	168: 'ErrorModule::UserlandCrash',
	180: 'ErrorModule::SREPO',
	181: 'ErrorModule::Dauth',
	202: 'ErrorModule::HID',
	203: 'ErrorModule::LDN',
	205: 'ErrorModule::Irsensor',
	206: 'ErrorModule::Capture',
	208: 'ErrorModule::Manu',
	209: 'ErrorModule::ATK',
	212: 'ErrorModule::GRC',
	216: 'ErrorModule::Migration',
	217: 'ErrorModule::MigrationLdcServ',
	800: 'ErrorModule::GeneralWebApplet',
	809: 'ErrorModule::WifiWebAuthApplet',
	810: 'ErrorModule::WhitelistedApplet',
	811: 'ErrorModule::ShopN',
}

def pack(error_module, error_code):
	return (error_module & 0xff) | ((error_code & 0xfff) << 9)

def unpack(error):
	return error & 0xff, error >> 9

def parse_error(error_code):
    if error_code == None:
        print('Invalid error code specified!')
        return
    mod, code = unpack(error_code)
    module_name = ERROR_MODULES.get(mod, 'ErrorModule::Unknown%d'%mod)
    print('Module      : %s'%module_name)
    print('Module Code : %d'%mod)
    print('Code(dec)   : %d'%code)
    print('Code(hex)   : 0x%x'%code)
    print('Code(binary): 0b{0:b}'.format(code))
    print()
    print('constexpr ResultCode ERROR_PLACEHOLDER{%s, %d};'%(module_name, code))

def build_error(mod, error):
    if mod == None:
        print('Invalid error module specified!')
        return
    if error == None:
        print('Invalid error code specified!')
        return
    module_name = ERROR_MODULES.get(mod, 'ErrorModule::Unknown%d'%mod)
    print('Module      : %s'%module_name)
    print('Module Code : %d'%mod)
    code = pack(mod, error)
    print('Code(dec)   : %d'%code)
    print('Code(hex)   : 0x%x'%code)
    print('Code(binary): 0b{0:b}'.format(code))

def main():
    argv = sys.argv
    if len(argv) == 1:
        print('%s <error code>' % argv[0])
        print("OR")
        print('%s <module code> <error>' % argv[0])
        return
    if len(argv) == 2:
        parse_error(su.str_to_basenum(argv[1]))
        return
    
    if len(argv) >= 3:
        build_error(su.str_to_basenum(argv[1]), su.str_to_basenum(argv[2]))
        return
if __name__ == "__main__":
    main()
