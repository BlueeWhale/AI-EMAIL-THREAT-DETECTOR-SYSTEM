"""
Text preprocessing utilities for email cleaning and normalization
"""

import re
import html
import unicodedata
import nltk
import logging
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer, WordNetLemmatizer
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk import pos_tag
from collections import Counter
import string

# Configure logging
logger = logging.getLogger(__name__)

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
    nltk.data.find('corpora/wordnet')
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('punkt', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.download('wordnet', quiet=True)
    nltk.download('averaged_perceptron_tagger', quiet=True)
    logger.info("Downloaded required NLTK data")

class TextPreprocessor:
    """
    Comprehensive text preprocessing for email analysis
    """
    
    def __init__(self):
        self.stemmer = PorterStemmer()
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Additional custom stop words for email
        self.custom_stop_words = {
            'com', 'www', 'http', 'https', 'html', 'email', 'mail',
            'sent', 'received', 'from', 'to', 'subject', 'date',
            're', 'fw', 'fwd', 'am', 'pm', 'est', 'pst', 'gmt'
        }
        self.stop_words.update(self.custom_stop_words)
        
        # Common email patterns
        self.email_patterns = {
            'url': re.compile(r'https?://\S+|www\.\S+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'ip': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            'money': re.compile(r'\$\s?\d+(?:,\d{3})*(?:\.\d{2})?'),
            'percentage': re.compile(r'\d+\s?%'),
            'date': re.compile(r'\d{1,2}[/-]\d{1,2}[/-]\d{2,4}'),
            'time': re.compile(r'\d{1,2}:\d{2}\s?(?:am|pm)?'),
            'hashtag': re.compile(r'#\w+'),
            'mention': re.compile(r'@\w+')
        }
    
    def clean_text(self, text):
        """
        Basic text cleaning
        """
        if not text or not isinstance(text, str):
            return ""
        
        # Convert to string
        text = str(text)
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Normalize unicode characters
        text = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('utf-8', 'ignore')
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def remove_patterns(self, text, patterns=None, replace_with=' '):
        """
        Remove or replace specific patterns
        """
        if patterns is None:
            patterns = ['url', 'email', 'phone']
        
        for pattern_name in patterns:
            if pattern_name in self.email_patterns:
                text = self.email_patterns[pattern_name].sub(replace_with, text)
        
        return text
    
    def remove_punctuation(self, text, keep_apostrophe=True):
        """
        Remove punctuation from text
        """
        if keep_apostrophe:
            # Keep apostrophes for contractions
            punctuation = string.punctuation.replace("'", "")
        else:
            punctuation = string.punctuation
        
        translator = str.maketrans('', '', punctuation)
        return text.translate(translator)
    
    def remove_numbers(self, text):
        """
        Remove numbers from text
        """
        return re.sub(r'\d+', ' ', text)
    
    def remove_extra_spaces(self, text):
        """
        Remove extra spaces and trim
        """
        return ' '.join(text.split())
    
    def tokenize(self, text):
        """
        Tokenize text into words
        """
        try:
            return word_tokenize(text)
        except:
            # Fallback to simple splitting
            return text.split()
    
    def remove_stopwords(self, tokens):
        """
        Remove stop words from tokens
        """
        return [token for token in tokens if token not in self.stop_words and len(token) > 1]
    
    def stem_tokens(self, tokens):
        """
        Apply stemming to tokens
        """
        return [self.stemmer.stem(token) for token in tokens]
    
    def lemmatize_tokens(self, tokens, pos_tags=None):
        """
        Apply lemmatization to tokens with optional POS tags
        """
        if pos_tags:
            lemmatized = []
            for token, pos in zip(tokens, pos_tags):
                # Convert POS tag for WordNet
                wn_pos = self._get_wordnet_pos(pos)
                lemmatized.append(self.lemmatizer.lemmatize(token, wn_pos))
            return lemmatized
        else:
            return [self.lemmatizer.lemmatize(token) for token in tokens]
    
    def _get_wordnet_pos(self, treebank_tag):
        """
        Convert treebank POS tag to WordNet POS tag
        """
        from nltk.corpus import wordnet
        
        if treebank_tag.startswith('J'):
            return wordnet.ADJ
        elif treebank_tag.startswith('V'):
            return wordnet.VERB
        elif treebank_tag.startswith('N'):
            return wordnet.NOUN
        elif treebank_tag.startswith('R'):
            return wordnet.ADV
        else:
            return wordnet.NOUN
    
    def extract_features(self, text):
        """
        Extract additional features from text
        """
        features = {}
        
        # Basic stats
        features['char_count'] = len(text)
        features['word_count'] = len(text.split())
        features['sentence_count'] = len(sent_tokenize(text)) if text else 0
        
        # Case analysis
        features['uppercase_count'] = sum(1 for c in text if c.isupper())
        features['uppercase_ratio'] = features['uppercase_count'] / features['char_count'] if features['char_count'] > 0 else 0
        
        # Punctuation analysis
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['punctuation_count'] = sum(1 for c in text if c in string.punctuation)
        
        # Special character counts
        features['url_count'] = len(self.email_patterns['url'].findall(text))
        features['email_count'] = len(self.email_patterns['email'].findall(text))
        features['phone_count'] = len(self.email_patterns['phone'].findall(text))
        features['money_count'] = len(self.email_patterns['money'].findall(text))
        
        # HTML/script detection
        features['has_html'] = 1 if re.search(r'<[^>]+>', text) else 0
        features['has_javascript'] = 1 if re.search(r'javascript:', text, re.IGNORECASE) else 0
        
        return features
    
    def extract_keywords(self, text, top_n=10):
        """
        Extract important keywords from text
        """
        # Clean and tokenize
        cleaned = self.clean_text(text)
        cleaned = self.remove_patterns(cleaned, ['url', 'email'])
        tokens = self.tokenize(cleaned)
        
        # Remove stopwords and short tokens
        filtered = [t for t in tokens if t not in self.stop_words and len(t) > 2]
        
        # Count frequencies
        word_freq = Counter(filtered)
        
        # Get top keywords
        keywords = word_freq.most_common(top_n)
        
        return [{'word': word, 'count': count} for word, count in keywords]
    
    def extract_entities(self, text):
        """
        Extract named entities (simplified version)
        """
        entities = {
            'urls': self.email_patterns['url'].findall(text),
            'emails': self.email_patterns['email'].findall(text),
            'phones': self.email_patterns['phone'].findall(text),
            'money': self.email_patterns['money'].findall(text),
            'dates': self.email_patterns['date'].findall(text),
            'times': self.email_patterns['time'].findall(text),
            'hashtags': self.email_patterns['hashtag'].findall(text),
            'mentions': self.email_patterns['mention'].findall(text)
        }
        
        return entities
    
    def normalize_text(self, text, options=None):
        """
        Complete text normalization pipeline
        """
        if options is None:
            options = {
                'clean': True,
                'remove_patterns': True,
                'remove_punctuation': True,
                'remove_numbers': False,
                'lowercase': True,
                'remove_stopwords': True,
                'stem': False,
                'lemmatize': True
            }
        
        # Start with original text
        result = text
        
        # Clean text
        if options.get('clean', True):
            result = self.clean_text(result)
        
        # Remove patterns
        if options.get('remove_patterns', True):
            result = self.remove_patterns(result)
        
        # Remove numbers
        if options.get('remove_numbers', False):
            result = self.remove_numbers(result)
        
        # Remove punctuation
        if options.get('remove_punctuation', True):
            result = self.remove_punctuation(result)
        
        # Tokenize
        tokens = self.tokenize(result)
        
        # Remove stopwords
        if options.get('remove_stopwords', True):
            tokens = self.remove_stopwords(tokens)
        
        # Apply stemming or lemmatization
        if options.get('stem', False):
            tokens = self.stem_tokens(tokens)
        elif options.get('lemmatize', True):
            # Get POS tags for better lemmatization
            try:
                pos_tags = pos_tag(tokens)
                pos_tags = [tag for word, tag in pos_tags]
                tokens = self.lemmatize_tokens(tokens, pos_tags)
            except:
                tokens = self.lemmatize_tokens(tokens)
        
        # Join tokens
        result = ' '.join(tokens)
        
        # Remove extra spaces
        result = self.remove_extra_spaces(result)
        
        return result
    
    def preprocess(self, text, return_features=False):
        """
        Main preprocessing function - standard pipeline
        """
        if not text:
            return "" if not return_features else ("", {})
        
        # Extract features if requested
        features = self.extract_features(text) if return_features else None
        
        # Normalize text
        normalized = self.normalize_text(text)
        
        if return_features:
            return normalized, features
        else:
            return normalized
    
    def preprocess_batch(self, texts, return_features=False):
        """
        Preprocess multiple texts
        """
        results = []
        for text in texts:
            results.append(self.preprocess(text, return_features))
        return results
    
    def get_metadata(self):
        """
        Get preprocessor metadata
        """
        return {
            'stop_words_count': len(self.stop_words),
            'stemmer': type(self.stemmer).__name__,
            'lemmatizer': type(self.lemmatizer).__name__,
            'patterns': list(self.email_patterns.keys())
        }

# Create singleton instance
preprocessor = TextPreprocessor()

# Additional utility functions for common preprocessing tasks

def clean_email(email_text):
    """
    Quick email cleaning function
    """
    return preprocessor.preprocess(email_text)

def extract_email_features(email_text):
    """
    Extract features from email
    """
    return preprocessor.extract_features(email_text)

def get_email_keywords(email_text, top_n=10):
    """
    Get important keywords from email
    """
    return preprocessor.extract_keywords(email_text, top_n)

def normalize_for_training(text):
    """
    Normalize text specifically for ML training
    """
    options = {
        'clean': True,
        'remove_patterns': True,
        'remove_punctuation': True,
        'remove_numbers': False,
        'lowercase': True,
        'remove_stopwords': True,
        'stem': False,
        'lemmatize': True
    }
    return preprocessor.normalize_text(text, options)

def normalize_for_display(text):
    """
    Light normalization for display purposes
    """
    options = {
        'clean': True,
        'remove_patterns': False,
        'remove_punctuation': False,
        'remove_numbers': False,
        'lowercase': False,
        'remove_stopwords': False,
        'stem': False,
        'lemmatize': False
    }
    return preprocessor.normalize_text(text, options)

# Test function
def test_preprocessor():
    """
    Test the preprocessor with sample text
    """
    test_texts = [
        "Check out this amazing offer! Click here: http://spam.com",
        "Meeting at 3pm tomorrow. Please bring the reports.",
        "URGENT: Your PayPal account has been limited! Verify now.",
        "Hi John, can you review the attached document? Thanks!",
        "WINNER! You've won $1,000,000. Claim at www.lottery.com"
    ]
    
    print("=" * 60)
    print("TESTING TEXT PREPROCESSOR")
    print("=" * 60)
    
    for i, text in enumerate(test_texts, 1):
        print(f"\n{i}. Original: {text}")
        
        # Basic preprocessing
        processed = preprocessor.preprocess(text)
        print(f"   Processed: {processed}")
        
        # Extract features
        features = preprocessor.extract_features(text)
        print(f"   Features: {features}")
        
        # Extract keywords
        keywords = preprocessor.extract_keywords(text, 3)
        print(f"   Keywords: {keywords}")
        
        # Extract entities
        entities = preprocessor.extract_entities(text)
        print(f"   Entities: {entities}")
        
        print("-" * 40)
    
    print("\n" + "=" * 60)
    print("Preprocessor Metadata:")
    print(preprocessor.get_metadata())
    print("=" * 60)

if __name__ == "__main__":
    # Run test if script is executed directly
    test_preprocessor()