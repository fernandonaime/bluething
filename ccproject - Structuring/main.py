from controls.tester import *
def main():
    try:
        banner()
        log_setup()
        home_main()
    except KeyboardInterrupt:
        print("\n\nExited unexpectedly...")
        exit()
    except Exception as e:
        print("Error:", e)


main()
