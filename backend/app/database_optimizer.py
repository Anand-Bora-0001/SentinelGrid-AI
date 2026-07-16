"""
SentinelGrid Database Optimizer
Implements database performance optimization, indexing, and query analysis
"""
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy import text, Index, inspect
from sqlalchemy.orm import Session
from sqlalchemy.engine import Engine
from dataclasses import dataclass
from .database import engine, get_db
from .models import SecurityEvent, Organization, User, Service

logger = logging.getLogger(__name__)

@dataclass
class QueryMetrics:
    """Query performance metrics"""
    execution_time: float
    rows_examined: int
    index_usage: bool
    optimization_suggestions: List[str]
    query_plan: Optional[str] = None

@dataclass
class IndexInfo:
    """Database index information"""
    table_name: str
    index_name: str
    columns: List[str]
    is_unique: bool
    size_estimate: Optional[int] = None

class QueryAnalyzer:
    """Analyzes query execution plans and performance"""
    
    def __init__(self, engine: Engine):
        self.engine = engine
        self.query_cache = {}
        self.performance_history = []
    
    def analyze_query_performance(self, query: str, params: Optional[Dict] = None) -> QueryMetrics:
        """Analyze query performance and execution plan"""
        try:
            start_time = time.time()
            
            with self.engine.connect() as conn:
                # Execute EXPLAIN QUERY PLAN for SQLite
                explain_query = f"EXPLAIN QUERY PLAN {query}"
                explain_result = conn.execute(text(explain_query), params or {})
                query_plan = [dict(row._mapping) for row in explain_result]
                
                # Execute the actual query to measure performance
                result = conn.execute(text(query), params or {})
                rows = result.fetchall()
                
                execution_time = time.time() - start_time
                rows_examined = len(rows)
                
                # Analyze query plan for index usage
                index_usage = self._check_index_usage(query_plan)
                suggestions = self._generate_optimization_suggestions(query, query_plan, execution_time)
                
                metrics = QueryMetrics(
                    execution_time=execution_time,
                    rows_examined=rows_examined,
                    index_usage=index_usage,
                    optimization_suggestions=suggestions,
                    query_plan=str(query_plan)
                )
                
                # Store in performance history
                self.performance_history.append({
                    'timestamp': datetime.now(),
                    'query': query[:100],  # Truncate for storage
                    'metrics': metrics
                })
                
                # Keep only last 1000 entries
                if len(self.performance_history) > 1000:
                    self.performance_history = self.performance_history[-1000:]
                
                return metrics
                
        except Exception as e:
            logger.error(f"Query analysis failed: {e}")
            return QueryMetrics(
                execution_time=0.0,
                rows_examined=0,
                index_usage=False,
                optimization_suggestions=[f"Analysis failed: {str(e)}"]
            )
    
    def _check_index_usage(self, query_plan: List[Dict]) -> bool:
        """Check if query plan uses indexes"""
        for step in query_plan:
            detail = step.get('detail', '').lower()
            if 'using index' in detail or 'index' in detail:
                return True
        return False
    
    def _generate_optimization_suggestions(self, query: str, query_plan: List[Dict], execution_time: float) -> List[str]:
        """Generate optimization suggestions based on query analysis"""
        suggestions = []
        
        # Check execution time
        if execution_time > 0.1:  # 100ms threshold
            suggestions.append(f"Query execution time ({execution_time:.3f}s) exceeds recommended threshold")
        
        # Check for table scans
        for step in query_plan:
            detail = step.get('detail', '').lower()
            if 'scan table' in detail and 'using index' not in detail:
                table_name = self._extract_table_name(detail)
                suggestions.append(f"Consider adding index to table '{table_name}' for better performance")
        
        # Check for common optimization opportunities
        query_lower = query.lower()
        if 'order by' in query_lower and 'limit' in query_lower:
            suggestions.append("Consider adding composite index for ORDER BY + LIMIT queries")
        
        if 'group by' in query_lower:
            suggestions.append("Consider adding index on GROUP BY columns")
        
        if 'where' in query_lower and 'and' in query_lower:
            suggestions.append("Consider adding composite index for multi-column WHERE conditions")
        
        return suggestions
    
    def _extract_table_name(self, detail: str) -> str:
        """Extract table name from query plan detail"""
        # Simple extraction for SQLite query plans
        parts = detail.split()
        for i, part in enumerate(parts):
            if part.lower() == 'table' and i + 1 < len(parts):
                return parts[i + 1]
        return "unknown"
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance analysis summary"""
        if not self.performance_history:
            return {"message": "No performance data available"}
        
        recent_queries = self.performance_history[-100:]  # Last 100 queries
        
        avg_execution_time = sum(q['metrics'].execution_time for q in recent_queries) / len(recent_queries)
        slow_queries = [q for q in recent_queries if q['metrics'].execution_time > 0.1]
        index_usage_rate = sum(1 for q in recent_queries if q['metrics'].index_usage) / len(recent_queries)
        
        return {
            'total_queries_analyzed': len(self.performance_history),
            'recent_queries_count': len(recent_queries),
            'average_execution_time': avg_execution_time,
            'slow_queries_count': len(slow_queries),
            'index_usage_rate': index_usage_rate,
            'common_suggestions': self._get_common_suggestions(recent_queries)
        }
    
    def _get_common_suggestions(self, queries: List[Dict]) -> List[str]:
        """Get most common optimization suggestions"""
        suggestion_counts = {}
        for query in queries:
            for suggestion in query['metrics'].optimization_suggestions:
                suggestion_counts[suggestion] = suggestion_counts.get(suggestion, 0) + 1
        
        # Return top 5 most common suggestions
        return sorted(suggestion_counts.items(), key=lambda x: x[1], reverse=True)[:5]

class IndexManager:
    """Manages database indexes for optimal performance"""
    
    def __init__(self, engine: Engine):
        self.engine = engine
        self.recommended_indexes = [
            # Attack events indexes
            IndexInfo("security_events", "idx_security_events_timestamp", ["timestamp"], False),
            IndexInfo("security_events", "idx_security_events_source_ip", ["source_ip"], False),
            IndexInfo("security_events", "idx_security_events_severity", ["severity"], False),
            IndexInfo("security_events", "idx_security_events_service_name", ["service_name"], False),
            IndexInfo("security_events", "idx_security_events_org_timestamp", ["organization_id", "timestamp"], False),
            IndexInfo("security_events", "idx_security_events_severity_timestamp", ["severity", "timestamp"], False),
            IndexInfo("security_events", "idx_security_events_ip_service", ["source_ip", "service_name"], False),
            
            # User and organization indexes
            IndexInfo("users", "idx_users_org_id", ["organization_id"], False),
            IndexInfo("services", "idx_services_org_id", ["organization_id"], False),
            IndexInfo("services", "idx_services_api_key", ["api_key"], True),
        ]
    
    def create_performance_indexes(self) -> Dict[str, bool]:
        """Create recommended performance indexes"""
        results = {}
        
        try:
            with self.engine.connect() as conn:
                # Get existing indexes
                existing_indexes = self._get_existing_indexes(conn)
                
                for index_info in self.recommended_indexes:
                    index_key = f"{index_info.table_name}.{index_info.index_name}"
                    
                    if index_key in existing_indexes:
                        logger.info(f"Index already exists: {index_info.index_name}")
                        results[index_info.index_name] = True
                        continue
                    
                    try:
                        # Create index
                        columns_str = ", ".join(index_info.columns)
                        unique_str = "UNIQUE " if index_info.is_unique else ""
                        
                        create_index_sql = f"""
                        CREATE {unique_str}INDEX IF NOT EXISTS {index_info.index_name}
                        ON {index_info.table_name} ({columns_str})
                        """
                        
                        conn.execute(text(create_index_sql))
                        conn.commit()
                        
                        logger.info(f"Created index: {index_info.index_name}")
                        results[index_info.index_name] = True
                        
                    except Exception as e:
                        logger.error(f"Failed to create index {index_info.index_name}: {e}")
                        results[index_info.index_name] = False
                        
        except Exception as e:
            logger.error(f"Index creation failed: {e}")
            
        return results
    
    def _get_existing_indexes(self, conn) -> Set[str]:
        """Get list of existing indexes"""
        existing_indexes = set()
        
        try:
            # Query SQLite master table for indexes
            result = conn.execute(text("""
                SELECT name, tbl_name FROM sqlite_master 
                WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
            """))
            
            for row in result:
                index_name = row[0]
                table_name = row[1]
                existing_indexes.add(f"{table_name}.{index_name}")
                
        except Exception as e:
            logger.error(f"Failed to get existing indexes: {e}")
            
        return existing_indexes
    
    def analyze_index_usage(self) -> Dict[str, Any]:
        """Analyze index usage statistics"""
        try:
            with self.engine.connect() as conn:
                # Get index information
                indexes = []
                
                result = conn.execute(text("""
                    SELECT name, tbl_name, sql FROM sqlite_master 
                    WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
                    ORDER BY tbl_name, name
                """))
                
                for row in result:
                    indexes.append({
                        'name': row[0],
                        'table': row[1],
                        'definition': row[2]
                    })
                
                return {
                    'total_indexes': len(indexes),
                    'indexes': indexes,
                    'recommendations': self._get_index_recommendations()
                }
                
        except Exception as e:
            logger.error(f"Index analysis failed: {e}")
            return {'error': str(e)}
    
    def _get_index_recommendations(self) -> List[str]:
        """Get index recommendations based on common query patterns"""
        recommendations = []
        
        # Check if recommended indexes exist
        with self.engine.connect() as conn:
            existing_indexes = self._get_existing_indexes(conn)
            
            for index_info in self.recommended_indexes:
                index_key = f"{index_info.table_name}.{index_info.index_name}"
                if index_key not in existing_indexes:
                    recommendations.append(
                        f"Create index {index_info.index_name} on {index_info.table_name}({', '.join(index_info.columns)})"
                    )
        
        return recommendations

class DatabaseOptimizer:
    """Main database optimization coordinator"""
    
    def __init__(self):
        self.query_analyzer = QueryAnalyzer(engine)
        self.index_manager = IndexManager(engine)
        self.optimization_history = []
    
    def optimize_database(self) -> Dict[str, Any]:
        """Perform comprehensive database optimization"""
        optimization_start = time.time()
        results = {
            'timestamp': datetime.now().isoformat(),
            'operations': [],
            'performance_improvement': {},
            'recommendations': []
        }
        
        try:
            # 1. Create performance indexes
            logger.info("Creating performance indexes...")
            index_results = self.index_manager.create_performance_indexes()
            results['operations'].append({
                'operation': 'create_indexes',
                'success': all(index_results.values()),
                'details': index_results
            })
            
            # 2. Analyze current performance
            logger.info("Analyzing query performance...")
            performance_summary = self.query_analyzer.get_performance_summary()
            results['operations'].append({
                'operation': 'analyze_performance',
                'success': True,
                'details': performance_summary
            })
            
            # 3. Optimize table structure (if needed)
            logger.info("Analyzing table structure...")
            table_analysis = self._analyze_table_structure()
            results['operations'].append({
                'operation': 'analyze_tables',
                'success': True,
                'details': table_analysis
            })
            
            # 4. Generate recommendations
            recommendations = self._generate_optimization_recommendations()
            results['recommendations'] = recommendations
            
            optimization_time = time.time() - optimization_start
            results['optimization_time'] = optimization_time
            
            # Store in history
            self.optimization_history.append(results)
            
            logger.info(f"Database optimization completed in {optimization_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_table_structure(self) -> Dict[str, Any]:
        """Analyze table structure and statistics"""
        try:
            with self.engine.connect() as conn:
                tables_info = {}
                
                # Get table information
                tables = ['security_events', 'users', 'organizations', 'services']
                
                for table in tables:
                    try:
                        # Get row count
                        count_result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        row_count = count_result.scalar()
                        
                        # Get table info
                        pragma_result = conn.execute(text(f"PRAGMA table_info({table})"))
                        columns = [dict(row._mapping) for row in pragma_result]
                        
                        tables_info[table] = {
                            'row_count': row_count,
                            'column_count': len(columns),
                            'columns': columns
                        }
                        
                    except Exception as e:
                        logger.error(f"Failed to analyze table {table}: {e}")
                        tables_info[table] = {'error': str(e)}
                
                return tables_info
                
        except Exception as e:
            logger.error(f"Table structure analysis failed: {e}")
            return {'error': str(e)}
    
    def _generate_optimization_recommendations(self) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        try:
            # Get index recommendations
            index_recommendations = self.index_manager._get_index_recommendations()
            recommendations.extend(index_recommendations)
            
            # Add general recommendations
            recommendations.extend([
                "Consider implementing query result caching for frequently accessed data",
                "Monitor query performance regularly and optimize slow queries",
                "Implement database connection pooling for better resource management",
                "Consider partitioning large tables if data volume grows significantly",
                "Regular VACUUM operations to optimize database file structure"
            ])
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}")
            recommendations.append(f"Recommendation generation failed: {e}")
        
        return recommendations
    
    def get_optimization_history(self) -> List[Dict]:
        """Get database optimization history"""
        return self.optimization_history[-10:]  # Last 10 optimizations
    
    def benchmark_queries(self) -> Dict[str, Any]:
        """Benchmark common queries for performance testing"""
        benchmarks = {}
        
        common_queries = {
            'recent_attacks': """
                SELECT * FROM security_events 
                WHERE timestamp > datetime('now', '-1 hour') 
                ORDER BY timestamp DESC LIMIT 100
            """,
            'attacks_by_severity': """
                SELECT severity, COUNT(*) as count 
                FROM security_events 
                GROUP BY severity
            """,
            'attacks_by_ip': """
                SELECT source_ip, COUNT(*) as count 
                FROM security_events 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY source_ip 
                ORDER BY count DESC LIMIT 50
            """,
            'user_organization_join': """
                SELECT u.username, o.name as org_name 
                FROM users u 
                JOIN organizations o ON u.organization_id = o.id 
                LIMIT 100
            """
        }
        
        for query_name, query in common_queries.items():
            try:
                metrics = self.query_analyzer.analyze_query_performance(query)
                benchmarks[query_name] = {
                    'execution_time': metrics.execution_time,
                    'rows_examined': metrics.rows_examined,
                    'index_usage': metrics.index_usage,
                    'suggestions': metrics.optimization_suggestions
                }
            except Exception as e:
                benchmarks[query_name] = {'error': str(e)}
        
        return benchmarks

# Global database optimizer instance
database_optimizer = DatabaseOptimizer()
