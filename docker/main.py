import traceback
from external_import_connector.connector import ConnectorIPSUM


def main():
    try:
        connector = ConnectorIPSUM()
        connector.run()  
    except Exception as e:
        print("[ERROR] Connector failed with exception:")
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
