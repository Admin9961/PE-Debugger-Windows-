import logging
import re
import pefile
import hashlib
import os
import humanize
import datetime

logging.basicConfig(level=logging.DEBUG, filename='debug_log.txt', filemode='w', format='%(asctime)s - %(levelname)s - %(message)s')
humanize.i18n.activate('it_IT')

class Win32Debugger:
    def __init__(self, executable_path):
        self.executable_path = executable_path

    def start_static_scan(self):
        self.static_scan()
        self.calculate_file_hash()
        self.analyze_strings()
        self.detect_imported_dlls()
        self.detect_resources()

    def static_scan(self):
        try:
            pe = pefile.PE(self.executable_path)
            arch = pe.FILE_HEADER.Machine

            if arch == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                logging.info("Architettura dell'exe: x86")
            elif arch == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                logging.info("Architettura dell'exe: x64")
            else:
                logging.warning("Architettura non supportata o sconosciuta")

            logging.info(f"Oggetto linker: {pe.FILE_HEADER.NumberOfSections}")
            logging.info(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
            logging.info(f"EntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

            logging.info("\nSezioni:")
            for section in pe.sections:
                logging.info(f"Nome: {section.Name.decode('utf-8').rstrip('\x00')}")
                logging.info(f"VirtualSize: {section.Misc_VirtualSize}")
                logging.info(f"VirtualAddress: {hex(section.VirtualAddress)}")
                logging.info(f"SizeOfRawData: {section.SizeOfRawData}")
                logging.info(f"Characteristics: {hex(section.Characteristics)}")

                permissions = []
                if section.Characteristics & 0x40000000:
                    permissions.append("Readable")
                if section.Characteristics & 0x20000000:
                    permissions.append("Writable")
                if section.Characteristics & 0x10000000:
                    permissions.append("Executable")

                logging.info(f"Permessi: {', '.join(permissions)}")

            file_size = os.path.getsize(self.executable_path)
            logging.info(f"Dimensione del file: {humanize.naturalsize(file_size)}")

            creation_time = datetime.datetime.fromtimestamp(os.path.getctime(self.executable_path))
            logging.info(f"Data e Ora di Creazione: {creation_time}")

            logging.info(f"Sistema operativo target: {self.detect_target_os(pe)}")
            logging.info(f"Versione del linker: {self.detect_linker_version(pe)}")

        except Exception as e:
            logging.error(f"Errore durante la scansione statica: {str(e)}")

    def calculate_file_hash(self, algorithm='sha256'):
        try:
            with open(self.executable_path, 'rb') as file:
                hash_algorithm = hashlib.new(algorithm)
                for chunk in iter(lambda: file.read(4096), b''):
                    hash_algorithm.update(chunk)

                file_hash = hash_algorithm.hexdigest()
                logging.info(f"Hash del file ({algorithm}): {file_hash}")

        except Exception as e:
            logging.error(f"Errore durante il calcolo dell'hash del file: {str(e)}")

    def analyze_strings(self):
        try:
            pe = pefile.PE(self.executable_path)

            logging.info("\nAnalisi delle stringhe:")

            email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

            for section in pe.sections:
                string_data = section.get_data()
                strings = re.findall(b"[^\x00-\x1F\x7F-\xFF]{4,}", string_data)

                for string in strings:
                    string_value = string.decode('utf-8', errors='ignore')

                    ip_addresses = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', string_value)
                    if ip_addresses:
                        logging.warning(f"Indirizzo IP rilevato: {ip_addresses}")

                    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', string_value)
                    if urls:
                        logging.warning(f"URL rilevato: {urls}")

                    keys = re.findall(r'\b[A-Fa-f0-9]{32}\b', string_value)
                    if keys:
                        logging.warning(f"Chiave rilevata: {keys}")

                    emails = re.findall(email_regex, string_value)
                    if emails:
                        logging.warning(f"Indirizzo e-mail rilevato: {emails}")

        except Exception as e:
            logging.error(f"Errore durante l'analisi delle stringhe: {str(e)}")

    def detect_target_os(self, pe):
        if pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_GUI']:
            return "Windows GUI (Windows a 32/64 bit)"
        elif pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_WINDOWS_CUI']:
            return "Windows Console (Windows a 32/64 bit)"
        elif pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_POSIX_CUI']:
            return "Posix Console (Windows a 32/64 bit)"
        else:
            return "Sistema operativo non identificato"

    def detect_linker_version(self, pe):
        return f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

    def detect_imported_dlls(self):
        try:
            pe = pefile.PE(self.executable_path)

            logging.info("\nDLL importate:")

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                logging.info(f"Libreria: {entry.dll}")
                for imp in entry.imports:
                    logging.info(f" - {imp.name}")

        except Exception as e:
            logging.error(f"Errore durante la rilevazione delle DLL importate: {str(e)}")

    def detect_resources(self):
        try:
            pe = pefile.PE(self.executable_path)

            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_directory = pe.DIRECTORY_ENTRY_RESOURCE

                for resource_type in resource_directory.entries:
                    type_name = pefile.RESOURCE_TYPE.get(resource_type.id, 'Unknown Type')
                    logging.info(f"Tipo di risorsa: {type_name} ({resource_type.id})")

                    for resource_id in resource_type.directory.entries:
                        id_name = pefile.RESOURCE_ID.get(resource_id.id, 'Unknown ID')
                        logging.info(f"  ID della risorsa: {id_name} ({resource_id.id})")

                        if hasattr(resource_id.directory, 'entries'):
                            for resource_entry in resource_id.directory.entries:
                                resource_offset = resource_entry.data.struct.OffsetToData
                                resource_size = resource_entry.data.struct.Size
                                logging.info(f"    Risorsa trovata: Offset={resource_offset}, Size={resource_size}")

        except Exception as e:
            logging.error(f"Errore durante il rilevamento delle risorse: {str(e)}")

if __name__ == "__main__":
    try:
        executable_path = input("Inserisci il percorso dell'eseguibile: ")
        debugger = Win32Debugger(executable_path)
        debugger.start_static_scan()

    except Exception as e:
        logging.error(f"Errore: {str(e)}")