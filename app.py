import streamlit as st
import joblib
import pandas as pd
from tensorflow.keras.models import load_model

# Load the trained models
rf_model = joblib.load('rf_model.joblib')
precaution_model = joblib.load('precaution_model.joblib')

def get_prediction_label(prediction):
    labels = {
        1: "SHA (Secure Hash Algorithm)",
        2: "DFA (Differential Fault Analysis)",
        3: "SFA (Simple Fault Analysis)",
        4: "SYA (Symmetric Algorithm)",
        5: "VNA (Vulnerable Network Analysis)"
    }
    return labels.get(prediction, "Unknown")

def get_precaution_message(prediction):
    return precaution_model.get(prediction, ["Precaution information not available."])

# Streamlit UI
st.title('IOT-Vulnerability Detection')

# Input fields
second = st.text_input('Second:')
src = st.text_input('Source:')
dst = st.text_input('Destination:')
packetcount = st.text_input('Packet Count:')
src_ratio = st.text_input('Source Ratio:')
dst_ratio = st.text_input('Destination Ratio:')
src_duration_ratio = st.text_input('Source Duration Ratio:')
dst_duration_ratio = st.text_input('Destination Duration Ratio:')
TotalPacketDuration = st.text_input('Total Packet Duration:')
TotalPacketLenght = st.text_input('Total Packet Length:')
src_packet_ratio = st.text_input('Source Packet Ratio:')
dst_packet_ratio = st.text_input('Destination Packet Ratio:')
DioCount = st.text_input('Dio Count:')
DisCount = st.text_input('Dis Count:')
DaoCount = st.text_input('Dao Count:')
OtherMsg = st.text_input('Other Msg:')

if st.button('Predict'):
    # Create a DataFrame from the input data
    input_data = pd.DataFrame([{
        'second': second,
        'src': src,
        'dst': dst,
        'packetcount': packetcount,
        'src_ratio': src_ratio,
        'dst_ratio': dst_ratio,
        'src_duration_ratio': src_duration_ratio,
        'dst_duration_ratio': dst_duration_ratio,
        'TotalPacketDuration': TotalPacketDuration,
        'TotalPacketLenght': TotalPacketLenght,
        'src_packet_ratio': src_packet_ratio,
        'dst_packet_ratio': dst_packet_ratio,
        'DioCount': DioCount,
        'DisCount': DisCount,
        'DaoCount': DaoCount,
        'OtherMsg': OtherMsg
    }])

    # Make prediction
    prediction = rf_model.predict(input_data)
    prediction_label = get_prediction_label(int(prediction[0]))
    precaution_message = get_precaution_message(int(prediction[0]))

    # Display results
    st.subheader('Prediction:')
    st.write(prediction_label)

    st.subheader('Precautions:')
    for precaution in precaution_message:
        st.write(f"- {precaution}")
