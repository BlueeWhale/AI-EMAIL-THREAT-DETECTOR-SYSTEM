"""
History routes for managing user analysis history
"""

from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from utils.database import db
from models.user import AnalysisHistory
from datetime import datetime, timedelta
import logging
import csv
import io
import json
from sqlalchemy import func, desc

logger = logging.getLogger(__name__)
history_bp = Blueprint('history', __name__, url_prefix='/api/history')

@history_bp.route('/', methods=['GET'])
@login_required
def get_history():
    """Get user's analysis history with pagination and filtering"""
    
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Validate pagination
        if page < 1:
            page = 1
        if per_page < 1:
            per_page = 10
        if per_page > 100:
            per_page = 100
        
        # Filter parameters
        spam_filter = request.args.get('spam')
        category_filter = request.args.get('category')
        days = request.args.get('days', type=int)
        search = request.args.get('search', '').strip()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Build base query
        query = AnalysisHistory.query.filter_by(user_id=current_user.id)
        
        # Apply filters
        if spam_filter is not None:
            is_spam = spam_filter.lower() == 'true'
            query = query.filter_by(is_spam=is_spam)
        
        if category_filter:
            query = query.filter(AnalysisHistory.category.ilike(f'%{category_filter}%'))
        
        if days:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            query = query.filter(AnalysisHistory.created_at >= cutoff_date)
        
        if search:
            query = query.filter(
                db.or_(
                    AnalysisHistory.email_subject.ilike(f'%{search}%'),
                    AnalysisHistory.email_content.ilike(f'%{search}%'),
                    AnalysisHistory.category.ilike(f'%{search}%'),
                    AnalysisHistory.explanation.ilike(f'%{search}%')
                )
            )
        
        # Apply sorting
        if sort_by == 'confidence':
            if sort_order == 'asc':
                query = query.order_by(AnalysisHistory.confidence.asc())
            else:
                query = query.order_by(AnalysisHistory.confidence.desc())
        elif sort_by == 'category':
            if sort_order == 'asc':
                query = query.order_by(AnalysisHistory.category.asc())
            else:
                query = query.order_by(AnalysisHistory.category.desc())
        else:  # default: sort by created_at
            if sort_order == 'asc':
                query = query.order_by(AnalysisHistory.created_at.asc())
            else:
                query = query.order_by(AnalysisHistory.created_at.desc())
        
        # Get total count before pagination
        total = query.count()
        
        # Get paginated results
        paginated = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Calculate summary stats
        total_spam = AnalysisHistory.query.filter_by(
            user_id=current_user.id, 
            is_spam=True
        ).count()
        
        total_phishing = AnalysisHistory.query.filter_by(
            user_id=current_user.id, 
            category='Phishing'
        ).count()
        
        # Get date range
        oldest = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(
            AnalysisHistory.created_at.asc()
        ).first()
        
        newest = AnalysisHistory.query.filter_by(user_id=current_user.id).order_by(
            AnalysisHistory.created_at.desc()
        ).first()
        
        return jsonify({
            'success': True,
            'history': [item.to_dict() for item in paginated],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'has_next': page * per_page < total,
                'has_prev': page > 1
            },
            'filters': {
                'spam': spam_filter,
                'category': category_filter,
                'days': days,
                'search': search,
                'sort_by': sort_by,
                'sort_order': sort_order
            },
            'summary': {
                'total': total,
                'spam': total_spam,
                'phishing': total_phishing,
                'legitimate': total - total_spam,
                'spam_percentage': round((total_spam / total * 100) if total > 0 else 0, 2),
                'date_range': {
                    'oldest': oldest.created_at.isoformat() if oldest else None,
                    'newest': newest.created_at.isoformat() if newest else None
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"History fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch history'}), 500

@history_bp.route('/<int:history_id>', methods=['GET'])
@login_required
def get_history_item(history_id):
    """Get specific history item with full content"""
    
    try:
        # Find history item
        item = AnalysisHistory.query.filter_by(
            id=history_id, 
            user_id=current_user.id
        ).first()
        
        if not item:
            return jsonify({'error': 'History item not found'}), 404
        
        # Return full details
        import json
        return jsonify({
            'success': True,
            'id': item.id,
            'email_subject': item.email_subject,
            'email_content': item.email_content,
            'email_from': item.email_from,
            'email_to': item.email_to,
            'email_date': item.email_date.isoformat() if item.email_date else None,
            'is_spam': item.is_spam,
            'confidence': round(item.confidence * 100, 2) if item.confidence else 0,
            'probability_spam': round(item.probability_spam * 100, 2) if item.probability_spam else 0,
            'probability_ham': round(item.probability_ham * 100, 2) if item.probability_ham else 0,
            'category': item.category,
            'explanation': item.explanation,
            'processing_time': item.processing_time,
            'model_version': item.model_version,
            'created_at': item.created_at.isoformat() if item.created_at else None,
            'detected_keywords': json.loads(item.detected_keywords) if item.detected_keywords else [],
            'risk_factors': json.loads(item.risk_factors) if item.risk_factors else [],
            'recommendations': json.loads(item.recommendations) if item.recommendations else [],
            'ip_address': item.ip_address,
            'user_agent': item.user_agent
        }), 200
        
    except Exception as e:
        logger.error(f"History item fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch history item'}), 500

@history_bp.route('/<int:history_id>', methods=['DELETE'])
@login_required
def delete_history_item(history_id):
    """Delete specific history item"""
    
    try:
        # Find history item
        item = AnalysisHistory.query.filter_by(
            id=history_id, 
            user_id=current_user.id
        ).first()
        
        if not item:
            return jsonify({'error': 'History item not found'}), 404
        
        # Delete item
        db.session.delete(item)
        db.session.commit()
        
        logger.info(f"User {current_user.username} deleted history item {history_id}")
        
        return jsonify({
            'success': True,
            'message': 'History item deleted successfully',
            'id': history_id
        }), 200
        
    except Exception as e:
        logger.error(f"History delete error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete history item'}), 500

@history_bp.route('/clear', methods=['DELETE'])
@login_required
def clear_history():
    """Clear all user's history"""
    
    try:
        # Delete all user's history
        deleted = AnalysisHistory.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        
        logger.info(f"User {current_user.username} cleared {deleted} history items")
        
        return jsonify({
            'success': True,
            'message': f'Successfully cleared {deleted} history items',
            'deleted_count': deleted
        }), 200
        
    except Exception as e:
        logger.error(f"History clear error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to clear history'}), 500

@history_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get detailed analysis statistics"""
    
    try:
        # Time periods
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        # Base query
        base_query = AnalysisHistory.query.filter_by(user_id=current_user.id)
        
        # Get counts for different periods
        stats = {
            'today': {
                'total': base_query.filter(AnalysisHistory.created_at >= today_start).count(),
                'spam': base_query.filter(
                    AnalysisHistory.created_at >= today_start,
                    AnalysisHistory.is_spam == True
                ).count()
            },
            'this_week': {
                'total': base_query.filter(AnalysisHistory.created_at >= week_ago).count(),
                'spam': base_query.filter(
                    AnalysisHistory.created_at >= week_ago,
                    AnalysisHistory.is_spam == True
                ).count()
            },
            'this_month': {
                'total': base_query.filter(AnalysisHistory.created_at >= month_ago).count(),
                'spam': base_query.filter(
                    AnalysisHistory.created_at >= month_ago,
                    AnalysisHistory.is_spam == True
                ).count()
            },
            'all_time': {
                'total': base_query.count(),
                'spam': base_query.filter_by(is_spam=True).count(),
                'phishing': base_query.filter_by(category='Phishing').count(),
                'legitimate': base_query.filter_by(is_spam=False).count()
            }
        }
        
        # Category breakdown
        categories = db.session.query(
            AnalysisHistory.category,
            func.count().label('count')
        ).filter_by(user_id=current_user.id).group_by(
            AnalysisHistory.category
        ).all()
        
        stats['category_breakdown'] = [
            {'category': cat, 'count': count} for cat, count in categories
        ]
        
        # Daily stats for chart
        daily = db.session.query(
            func.date(AnalysisHistory.created_at).label('date'),
            func.count().label('total'),
            func.sum(db.cast(AnalysisHistory.is_spam, db.Integer)).label('spam')
        ).filter(
            AnalysisHistory.user_id == current_user.id,
            AnalysisHistory.created_at >= month_ago
        ).group_by(
            func.date(AnalysisHistory.created_at)
        ).order_by(
            func.date(AnalysisHistory.created_at)
        ).all()
        
        stats['daily_stats'] = [{
            'date': str(d.date),
            'total': d.total,
            'spam': d.spam or 0,
            'legitimate': d.total - (d.spam or 0)
        } for d in daily]
        
        # Confidence distribution
        confidence_ranges = [
            (0, 20), (20, 40), (40, 60), (60, 80), (80, 100)
        ]
        
        confidence_stats = []
        for low, high in confidence_ranges:
            count = base_query.filter(
                AnalysisHistory.confidence >= low/100,
                AnalysisHistory.confidence < high/100
            ).count()
            confidence_stats.append({
                'range': f'{low}-{high}%',
                'count': count
            })
        
        stats['confidence_distribution'] = confidence_stats
        
        # Most active times
        hour_stats = db.session.query(
            func.strftime('%H', AnalysisHistory.created_at).label('hour'),
            func.count().label('count')
        ).filter_by(user_id=current_user.id).group_by('hour').all()
        
        stats['hourly_activity'] = [
            {'hour': int(h), 'count': c} for h, c in hour_stats
        ]
        
        # Average confidence
        avg_confidence = db.session.query(
            func.avg(AnalysisHistory.confidence)
        ).filter_by(user_id=current_user.id).scalar()
        
        stats['avg_confidence'] = round(avg_confidence * 100, 2) if avg_confidence else 0
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': now.isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Stats fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch statistics'}), 500

@history_bp.route('/export', methods=['GET'])
@login_required
def export_history():
    """Export history as CSV"""
    
    try:
        # Get all user's history
        history = AnalysisHistory.query.filter_by(
            user_id=current_user.id
        ).order_by(
            AnalysisHistory.created_at.desc()
        ).all()
        
        if not history:
            return jsonify({'error': 'No history to export'}), 404
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Date', 'Subject', 'Category', 'Is Spam', 
            'Confidence (%)', 'Explanation', 'Processing Time (s)'
        ])
        
        # Write data
        for item in history:
            writer.writerow([
                item.id,
                item.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                item.email_subject or '',
                item.category or '',
                'Yes' if item.is_spam else 'No',
                round(item.confidence * 100, 2) if item.confidence else 0,
                item.explanation or '',
                round(item.processing_time, 3) if item.processing_time else 0
            ])
        
        # Prepare response
        output.seek(0)
        filename = f"email_analysis_history_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({'error': 'Failed to export history'}), 500

@history_bp.route('/search', methods=['GET'])
@login_required
def search_history():
    """Search history with advanced filters"""
    
    try:
        # Search parameters
        query_params = request.args
        
        keyword = query_params.get('keyword', '').strip()
        category = query_params.get('category')
        date_from = query_params.get('from')
        date_to = query_params.get('to')
        min_confidence = query_params.get('min_confidence', type=float)
        max_confidence = query_params.get('max_confidence', type=float)
        
        # Build query
        query = AnalysisHistory.query.filter_by(user_id=current_user.id)
        
        if keyword:
            query = query.filter(
                db.or_(
                    AnalysisHistory.email_subject.ilike(f'%{keyword}%'),
                    AnalysisHistory.email_content.ilike(f'%{keyword}%'),
                    AnalysisHistory.explanation.ilike(f'%{keyword}%')
                )
            )
        
        if category:
            query = query.filter_by(category=category)
        
        if date_from:
            try:
                from_date = datetime.fromisoformat(date_from)
                query = query.filter(AnalysisHistory.created_at >= from_date)
            except:
                pass
        
        if date_to:
            try:
                to_date = datetime.fromisoformat(date_to)
                query = query.filter(AnalysisHistory.created_at <= to_date)
            except:
                pass
        
        if min_confidence is not None:
            query = query.filter(AnalysisHistory.confidence >= min_confidence/100)
        
        if max_confidence is not None:
            query = query.filter(AnalysisHistory.confidence <= max_confidence/100)
        
        # Execute query
        results = query.order_by(AnalysisHistory.created_at.desc()).limit(100).all()
        
        return jsonify({
            'success': True,
            'results': [item.to_dict() for item in results],
            'count': len(results),
            'filters': {
                'keyword': keyword,
                'category': category,
                'date_from': date_from,
                'date_to': date_to,
                'min_confidence': min_confidence,
                'max_confidence': max_confidence
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({'error': 'Failed to search history'}), 500

@history_bp.route('/recent', methods=['GET'])
@login_required
def get_recent():
    """Get recent analyses for dashboard"""
    
    try:
        limit = request.args.get('limit', 10, type=int)
        if limit > 50:
            limit = 50
        
        recent = AnalysisHistory.query.filter_by(
            user_id=current_user.id
        ).order_by(
            AnalysisHistory.created_at.desc()
        ).limit(limit).all()
        
        return jsonify({
            'success': True,
            'recent': [item.to_dict() for item in recent],
            'count': len(recent)
        }), 200
        
    except Exception as e:
        logger.error(f"Recent fetch error: {str(e)}")
        return jsonify({'error': 'Failed to fetch recent analyses'}), 500

@history_bp.route('/summary', methods=['GET'])
@login_required
def get_summary():
    """Get quick summary of user's history"""
    
    try:
        # Get counts
        total = AnalysisHistory.query.filter_by(user_id=current_user.id).count()
        
        if total == 0:
            return jsonify({
                'success': True,
                'summary': {
                    'has_data': False,
                    'message': 'No analysis history yet'
                }
            }), 200
        
        # Get recent activity
        last_week = total - AnalysisHistory.query.filter(
            AnalysisHistory.user_id == current_user.id,
            AnalysisHistory.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count()
        
        # Get top categories
        top_categories = db.session.query(
            AnalysisHistory.category,
            func.count().label('count')
        ).filter_by(user_id=current_user.id).group_by(
            AnalysisHistory.category
        ).order_by(
            func.count().desc()
        ).limit(3).all()
        
        return jsonify({
            'success': True,
            'summary': {
                'has_data': True,
                'total_analyses': total,
                'last_week_activity': last_week,
                'top_categories': [
                    {'category': cat, 'count': count} 
                    for cat, count in top_categories
                ],
                'last_analysis': AnalysisHistory.query.filter_by(
                    user_id=current_user.id
                ).order_by(
                    AnalysisHistory.created_at.desc()
                ).first().to_dict() if total > 0 else None
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Summary error: {str(e)}")
        return jsonify({'error': 'Failed to get summary'}), 500

@history_bp.route('/batch-delete', methods=['POST'])
@login_required
def batch_delete():
    """Delete multiple history items at once"""
    
    try:
        data = request.get_json()
        
        if not data or 'ids' not in data:
            return jsonify({'error': 'No IDs provided'}), 400
        
        ids = data['ids']
        
        if not isinstance(ids, list):
            return jsonify({'error': 'IDs must be a list'}), 400
        
        if len(ids) > 100:
            return jsonify({'error': 'Maximum 100 items per batch'}), 400
        
        # Delete items
        deleted = AnalysisHistory.query.filter(
            AnalysisHistory.user_id == current_user.id,
            AnalysisHistory.id.in_(ids)
        ).delete(synchronize_session=False)
        
        db.session.commit()
        
        logger.info(f"User {current_user.username} batch deleted {deleted} items")
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted} items',
            'deleted_count': deleted,
            'requested_count': len(ids)
        }), 200
        
    except Exception as e:
        logger.error(f"Batch delete error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete items'}), 500

@history_bp.route('/trends', methods=['GET'])
@login_required
def get_trends():
    """Get spam trends over time"""
    
    try:
        # Get data for last 90 days
        days = request.args.get('days', 90, type=int)
        if days > 365:
            days = 365
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Get monthly breakdown
        monthly = db.session.query(
            func.strftime('%Y-%m', AnalysisHistory.created_at).label('month'),
            func.count().label('total'),
            func.sum(db.cast(AnalysisHistory.is_spam, db.Integer)).label('spam')
        ).filter(
            AnalysisHistory.user_id == current_user.id,
            AnalysisHistory.created_at >= cutoff
        ).group_by(
            'month'
        ).order_by(
            'month'
        ).all()
        
        # Calculate trends
        spam_rate_trend = []
        for i, month in enumerate(monthly):
            rate = (month.spam / month.total * 100) if month.total > 0 else 0
            spam_rate_trend.append({
                'month': month.month,
                'spam_rate': round(rate, 2)
            })
        
        return jsonify({
            'success': True,
            'trends': {
                'monthly_breakdown': [
                    {
                        'month': m.month,
                        'total': m.total,
                        'spam': m.spam or 0,
                        'legitimate': m.total - (m.spam or 0),
                        'spam_rate': round((m.spam or 0) / m.total * 100, 2) if m.total > 0 else 0
                    } for m in monthly
                ],
                'spam_rate_trend': spam_rate_trend,
                'period_days': days
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Trends error: {str(e)}")
        return jsonify({'error': 'Failed to get trends'}), 500