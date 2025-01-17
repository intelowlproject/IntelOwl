import React from "react";

const PhishingAnalysis = () => {
    const handleDownload = () => {
        window.location.href = "/phishing-analysis/download/";
    };

    return (
        <div className="phishing-analysis-container">
            <h2>Phishing Analysis Playbook</h2>
            <p>Download the latest phishing analysis report for review and insights.</p>
            
            {/* Download Button */}
            <button onClick={handleDownload} className="btn btn-primary">
                Download Report
            </button>
        </div>
    );
};

export default PhishingAnalysis;
