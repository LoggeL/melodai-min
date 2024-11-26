from groq import Groq
import json
import os

# env
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.environ["GROQ_API_KEY"])


def chunk_lyrics(lyrics_id):
    # songs/{id}/lyrics.json
    lyrics_path = f"src/songs/{lyrics_id}/lyrics_merged.json"
    with open(lyrics_path, "r") as f:
        lyrics = json.load(f)

    # segments -> text -> join \n
    lyrics_text = "\n".join([segment["text"] for segment in lyrics["segments"]])

    completion = client.chat.completions.create(
        model="gemma2-9b-it",
        messages=[
            {
                "role": "system",
                "content": "You chunk lyrics into meaningful lines\nOnly return the lyrics in proper formatting",
            },
            {
                "role": "user",
                "content": lyrics_text,
            },
        ],
        temperature=0,
        top_p=1,
        stop=None,
    )

    formatted_lyrics_str = completion.choices[0].message.content

    # store txt versions of both
    with open(
        f"src/songs/{lyrics_id}/lyrics_formatted.txt", "w", encoding="utf-8"
    ) as f:
        f.write(formatted_lyrics_str)

    with open(f"src/songs/{lyrics_id}/lyrics.txt", "w", encoding="utf-8") as f:
        f.write(lyrics_text)

    #     "segments": [
    # {
    #     "end": 14.587,
    #     "speaker": "SPEAKER_00",
    #     "start": 11.144,
    #     "text": " I am the monster you created.",
    #     "words": [
    #         {
    #             "end": 11.204,
    #             "score": 0.801,
    #             "speaker": "SPEAKER_00",
    #             "start": 11.144,
    #             "word": "I"
    #         },

    formatted_segments = []
    original_segments = lyrics["segments"]
    current_segment_idx = 0
    current_word_idx = 0
    formatted_lines = formatted_lyrics_str.strip().split("\n")

    # Process each formatted line
    for formatted_line in formatted_lines:
        words = formatted_line.split()
        new_segment = {
            "text": formatted_line,
            "speaker": original_segments[current_segment_idx]["speaker"],
            "words": [],
        }

        # Add words from original segment until we match the formatted line
        while len(new_segment["words"]) < len(words):
            if current_word_idx >= len(original_segments[current_segment_idx]["words"]):
                current_segment_idx += 1
                current_word_idx = 0

            word_data = original_segments[current_segment_idx]["words"][
                current_word_idx
            ]
            new_segment["words"].append(word_data)
            current_word_idx += 1

        if len(new_segment["words"]) == 0:
            continue

        # Set start/end times based on first/last word
        if new_segment["words"]:
            new_segment["start"] = new_segment["words"][0].get("start", 0)
            new_segment["end"] = new_segment["words"][-1].get("end", 0)

        # start, end and speaker for new_segment based on its words
        for word in new_segment["words"]:
            if "start" in word:
                new_segment["start"] = min(new_segment["start"], word["start"])
            if "end" in word:
                new_segment["end"] = max(new_segment["end"], word["end"])

        # count speaker occurrences
        speaker_counts = {}
        for word in new_segment["words"]:
            if "speaker" in word:
                speaker_counts[word["speaker"]] = (
                    speaker_counts.get(word["speaker"], 0) + 1
                )
        # if non have been found set SPEAKER_00
        if len(speaker_counts) == 0:
            new_segment["speaker"] = "SPEAKER_00"
        else:
            new_segment["speaker"] = max(speaker_counts, key=speaker_counts.get)

        formatted_segments.append(new_segment)

    lyrics["segments"] = formatted_segments
    formatted_lyrics = lyrics

    # write to json
    with open(f"src/songs/{lyrics_id}/lyrics.json", "w", encoding="utf-8") as f:
        json.dump(formatted_lyrics, f)


def merge_lyrics(lyrics_id):
    # songs/{id}/lyrics.json
    lyrics_path = f"src/songs/{lyrics_id}/lyrics_raw.json"
    with open(lyrics_path, "r") as f:
        lyrics = json.load(f)

    old_segments = lyrics["segments"]
    new_segments = []

    for segment in old_segments:
        # sometimes the words are on a char based level but the text is correct. I want to merge the chars back to words.
        words = segment["text"].split(" ")
        if len(words) < len(segment["words"]):
            word_index = 0
            new_words = []
            for word in words:
                word_collector = []
                collected_text = ""
                while len(collected_text) < len(word):
                    word_collector.append(segment["words"][word_index])
                    collected_text += segment["words"][word_index]["word"]
                    word_index += 1

                new_word = {"word": collected_text}

                # merge to a single word
                # count speaker occurrences
                speaker_counts = {}
                for word in word_collector:
                    if "speaker" in word:
                        speaker_counts[word["speaker"]] = (
                            speaker_counts.get(word["speaker"], 0) + 1
                        )
                # if non have been found set SPEAKER_00
                if len(speaker_counts) == 0:
                    new_word["speaker"] = "SPEAKER_00"
                else:
                    new_word["speaker"] = max(speaker_counts, key=speaker_counts.get)

                # start, end and speaker for new_segment based on its words
                for word in word_collector:
                    if "start" in word:
                        new_word["start"] = min(
                            new_word.get("start", float("inf")), word["start"]
                        )
                    if "end" in word:
                        new_word["end"] = max(
                            new_word.get("end", float("-inf")), word["end"]
                        )

                new_words.append(new_word)

            segment["words"] = new_words
            new_segments.append(segment)

        else:
            new_segments.append(segment)

    lyrics["segments"] = new_segments

    # write to json
    with open(f"src/songs/{lyrics_id}/lyrics_merged.json", "w", encoding="utf-8") as f:
        json.dump(lyrics, f)


# Test
if __name__ == "__main__":
    # chunk_lyrics("2984775641")
    merge_lyrics("2867606132")