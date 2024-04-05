import speech_recognition as sr

def recognize_speech():
    # Initialize recognizer class (for recognizing the speech)
    recognizer = sr.Recognizer()

    # Capture the audio
    with sr.Microphone() as source:
        print("Listening...")

        # Adjust for ambient noise
        recognizer.adjust_for_ambient_noise(source)

        # Listen to the user's input
        audio = recognizer.listen(source)

    try:
        print("Recognizing...")
        # Recognize the speech using Google Speech Recognition
        text = recognizer.recognize_google(audio)
        return text
    except sr.UnknownValueError:
        print("Sorry, I couldn't understand what you said.")
        return None
    except sr.RequestError as e:
        print("Sorry, Google Speech Recognition service is down. {0}".format(e))
        return None

if __name__ == "__main__":
    recognized_text = recognize_speech()
    if recognized_text:
        print("You said:", recognized_text)
